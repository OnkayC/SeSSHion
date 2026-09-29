//! Native SSH-agent authentication. Every endpoint attempt has one deadline and
//! can request at most one signature, even when RSA needs multiple key probes.

use std::time::Duration;

use russh::client::Handle;

use super::config::AgentAuth;
use super::handler::SshHandler;
use crate::error::{Result, SshMcpError};

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;

    use russh::Signer;
    use russh::keys::agent::AgentIdentity;
    use russh::keys::agent::client::AgentClient;
    use russh::keys::{self, HashAlg, PublicKey};
    use tokio::net::UnixStream;
    use tokio::time::{Instant, timeout_at};
    use tracing::debug;

    use super::*;

    #[derive(Debug)]
    enum AgentAuthFailure {
        SocketUnavailable {
            socket: PathBuf,
            reason: String,
        },
        AgentEmpty,
        AmbiguousIdentities(Vec<String>),
        SelectorNotLoaded {
            selected: String,
            loaded: Vec<String>,
        },
        ServerRejectedKey(String),
        SigningRefused(String),
        ServerRejectedSignature(String),
        RsaSha2Unsupported,
        Timeout {
            budget: Duration,
            phase: &'static str,
        },
        AgentIo(&'static str),
        AgentProtocol(&'static str),
        SessionLost,
        RepeatedSignature,
    }

    impl AgentAuthFailure {
        fn into_error(self, stage: &str) -> SshMcpError {
            let message = match self {
                Self::SocketUnavailable { socket, reason } => format!(
                    "ssh-agent socket {} not reachable ({reason})", socket.display()
                ),
                Self::AgentEmpty => "ssh-agent has no usable public-key identities; certificate identities are not supported".to_string(),
                Self::AmbiguousIdentities(fingerprints) => format!(
                    "ssh-agent holds {} identities ({}); set {}",
                    fingerprints.len(), fingerprints.join(", "),
                    if stage.starts_with("jump") { "--jump-agent-identity" } else { "--agent-identity" }
                ),
                Self::SelectorNotLoaded { selected, loaded } => format!(
                    "selected identity {selected} is not loaded in ssh-agent; loaded public-key identities: {}",
                    if loaded.is_empty() { "none".to_string() } else { loaded.join(", ") }
                ),
                Self::ServerRejectedKey(fingerprint) => format!(
                    "server did not accept identity {fingerprint} (no signature requested)"
                ),
                Self::SigningRefused(fingerprint) => format!(
                    "ssh-agent refused to sign with {fingerprint}"
                ),
                Self::ServerRejectedSignature(fingerprint) => format!(
                    "server rejected the signature from {fingerprint}"
                ),
                Self::RsaSha2Unsupported => "server does not support rsa-sha2-256/512; SHA-1 is not used in agent mode".to_string(),
                Self::Timeout { budget, phase } => format!(
                    "timed out after {} ms waiting for {phase}", budget.as_millis()
                ),
                Self::AgentIo(phase) => format!("ssh-agent connection lost during {phase}"),
                Self::AgentProtocol(phase) => format!("ssh-agent returned an invalid response during {phase}"),
                Self::SessionLost => "SSH session ended during agent authentication".to_string(),
                Self::RepeatedSignature => "server requested more than one signature; no additional ssh-agent signing request was sent".to_string(),
            };
            SshMcpError::auth(format!("{stage}: {message}"))
        }
    }

    fn fingerprint(key: &PublicKey) -> String {
        key.fingerprint(HashAlg::Sha256).to_string()
    }

    fn eligible_keys(identities: &[AgentIdentity]) -> impl Iterator<Item = &PublicKey> {
        identities.iter().filter_map(|identity| match identity {
            AgentIdentity::PublicKey { key, .. } => Some(key),
            AgentIdentity::Certificate { .. } => None,
        })
    }

    fn select_identity<'a>(
        identities: &'a [AgentIdentity],
        selector: Option<&PublicKey>,
    ) -> std::result::Result<&'a PublicKey, AgentAuthFailure> {
        if let Some(selector) = selector {
            return eligible_keys(identities)
                .find(|key| key.key_data() == selector.key_data())
                .ok_or_else(|| AgentAuthFailure::SelectorNotLoaded {
                    selected: fingerprint(selector),
                    loaded: eligible_keys(identities).map(fingerprint).collect(),
                });
        }

        let mut keys = eligible_keys(identities);
        let first = keys.next().ok_or(AgentAuthFailure::AgentEmpty)?;
        if keys.next().is_some() {
            return Err(AgentAuthFailure::AmbiguousIdentities(
                eligible_keys(identities).map(fingerprint).collect(),
            ));
        }
        Ok(first)
    }

    fn rsa_hash_plan(
        advertised: Option<Option<HashAlg>>,
    ) -> std::result::Result<&'static [Option<HashAlg>], AgentAuthFailure> {
        match advertised {
            Some(Some(HashAlg::Sha512)) => Ok(&[Some(HashAlg::Sha512)]),
            Some(Some(HashAlg::Sha256)) => Ok(&[Some(HashAlg::Sha256)]),
            Some(None) | Some(Some(_)) => Err(AgentAuthFailure::RsaSha2Unsupported),
            None => Ok(&[Some(HashAlg::Sha512), Some(HashAlg::Sha256)]),
        }
    }

    #[derive(Debug, thiserror::Error)]
    enum SignerError {
        #[error(transparent)]
        Send(#[from] russh::SendError),
        #[error(transparent)]
        Key(#[from] keys::Error),
        #[error("a signature was already requested")]
        RepeatedSignature,
    }

    struct OneShotSigner {
        client: AgentClient<UnixStream>,
        sign_requested: bool,
        signature_returned: bool,
    }

    impl Signer for OneShotSigner {
        type Error = SignerError;

        async fn auth_sign(
            &mut self,
            key: &AgentIdentity,
            hash_alg: Option<HashAlg>,
            to_sign: Vec<u8>,
        ) -> std::result::Result<Vec<u8>, Self::Error> {
            if self.sign_requested {
                return Err(SignerError::RepeatedSignature);
            }
            // Set before awaiting: refusal, I/O failure, timeout, and cancellation
            // must all consume this attempt's single signing allowance.
            self.sign_requested = true;
            let signed = self.client.sign_request(key, hash_alg, to_sign).await?;
            self.signature_returned = true;
            Ok(signed)
        }
    }

    fn agent_error(error: keys::Error, phase: &'static str) -> AgentAuthFailure {
        match error {
            keys::Error::IO(_) => AgentAuthFailure::AgentIo(phase),
            _ => AgentAuthFailure::AgentProtocol(phase),
        }
    }

    pub(super) async fn authenticate(
        session: &mut Handle<SshHandler>,
        username: &str,
        auth: &AgentAuth,
        budget: Duration,
        stage: &str,
    ) -> Result<()> {
        authenticate_inner(session, username, auth, budget)
            .await
            .map_err(|failure| failure.into_error(stage))
    }

    async fn authenticate_inner(
        session: &mut Handle<SshHandler>,
        username: &str,
        auth: &AgentAuth,
        budget: Duration,
    ) -> std::result::Result<(), AgentAuthFailure> {
        let deadline = Instant::now() + budget;
        let mut client = timeout_at(deadline, AgentClient::connect_uds(&auth.socket))
            .await
            .map_err(|_| AgentAuthFailure::Timeout {
                budget,
                phase: "agent connect",
            })?
            .map_err(|error| AgentAuthFailure::SocketUnavailable {
                socket: auth.socket.clone(),
                reason: error.to_string(),
            })?;
        let identities = timeout_at(deadline, client.request_identities())
            .await
            .map_err(|_| AgentAuthFailure::Timeout {
                budget,
                phase: "identities",
            })?
            .map_err(|error| agent_error(error, "identities"))?;
        let key = select_identity(&identities, auth.identity.as_ref())?;
        let fingerprint = fingerprint(key);
        let hashes = if key.algorithm().is_rsa() {
            let advertised = timeout_at(deadline, session.best_supported_rsa_hash())
                .await
                .map_err(|_| AgentAuthFailure::Timeout {
                    budget,
                    phase: "server reply",
                })?
                .map_err(|_| AgentAuthFailure::SessionLost)?;
            rsa_hash_plan(advertised)?
        } else {
            &[None]
        };

        debug!(%fingerprint, algorithm = %key.algorithm(), "Selected ssh-agent identity");
        let mut signer = OneShotSigner {
            client,
            sign_requested: false,
            signature_returned: false,
        };
        for &hash in hashes {
            let result = timeout_at(
                deadline,
                session.authenticate_publickey_with(username, key.clone(), hash, &mut signer),
            )
            .await
            .map_err(|_| AgentAuthFailure::Timeout {
                budget,
                phase: if signer.sign_requested && !signer.signature_returned {
                    "signature"
                } else {
                    "server reply"
                },
            })?
            .map_err(|error| match error {
                SignerError::Key(keys::Error::AgentFailure) => {
                    AgentAuthFailure::SigningRefused(fingerprint.clone())
                }
                SignerError::Key(error) => agent_error(error, "signature"),
                SignerError::Send(_) => AgentAuthFailure::SessionLost,
                SignerError::RepeatedSignature => AgentAuthFailure::RepeatedSignature,
            })?;
            if result.success() {
                return Ok(());
            }
            if signer.sign_requested {
                return Err(AgentAuthFailure::ServerRejectedSignature(fingerprint));
            }
            // Only an unsigned RSA probe may advance to another hash.
        }
        Err(AgentAuthFailure::ServerRejectedKey(fingerprint))
    }

    #[cfg(test)]
    mod tests {
        use russh::keys::ssh_key::{certificate, private, public};

        use super::*;

        fn private_key(seed: u8) -> keys::PrivateKey {
            keys::PrivateKey::new(
                private::KeypairData::Ed25519(private::Ed25519Keypair::from_seed(&[seed; 32])),
                "test key",
            )
            .unwrap()
        }

        fn key(seed: u8, comment: &str) -> PublicKey {
            PublicKey::new(
                public::KeyData::Ed25519(public::Ed25519PublicKey([seed; 32])),
                comment,
            )
        }

        fn certificate(key: &PublicKey) -> AgentIdentity {
            let mut builder =
                certificate::Builder::new(vec![7; 16], key.key_data().clone(), 0, u64::MAX)
                    .unwrap();
            builder.valid_principal("test").unwrap();
            AgentIdentity::Certificate {
                certificate: builder.sign(&private_key(9)).unwrap(),
                comment: "certificate comment".to_string(),
            }
        }

        #[test]
        fn selection_counts_only_plain_keys_and_ignores_comments() {
            let selected = key(1, "loaded comment");
            let selector = key(1, "selector comment");
            let identities = [certificate(&selected), selected.clone().into()];
            assert_eq!(
                select_identity(&identities, None).unwrap().key_data(),
                selected.key_data()
            );
            assert_eq!(
                select_identity(&identities, Some(&selector))
                    .unwrap()
                    .key_data(),
                selected.key_data()
            );
            assert!(matches!(
                select_identity(&identities[..1], None),
                Err(AgentAuthFailure::AgentEmpty)
            ));
            assert!(matches!(
                select_identity(&identities[..1], Some(&selector)),
                Err(AgentAuthFailure::SelectorNotLoaded { .. })
            ));
        }

        #[test]
        fn selection_rejects_empty_ambiguous_and_missing_keys() {
            assert!(matches!(
                select_identity(&[], None),
                Err(AgentAuthFailure::AgentEmpty)
            ));
            let first = key(1, "secret comment one");
            let second = key(2, "secret comment two");
            let identities = [first.clone().into(), second.clone().into()];
            let error = select_identity(&identities, None).unwrap_err();
            let AgentAuthFailure::AmbiguousIdentities(fingerprints) = error else {
                panic!("expected ambiguity")
            };
            assert_eq!(fingerprints, [fingerprint(&first), fingerprint(&second)]);
            assert_eq!(
                select_identity(&identities, Some(&second))
                    .unwrap()
                    .key_data(),
                second.key_data()
            );
            let missing = key(3, "unused selector comment");
            let error = select_identity(&identities, Some(&missing)).unwrap_err();
            let AgentAuthFailure::SelectorNotLoaded { selected, loaded } = error else {
                panic!("expected missing selector")
            };
            assert_eq!(selected, fingerprint(&missing));
            assert_eq!(loaded, [fingerprint(&first), fingerprint(&second)]);
        }

        #[test]
        fn rsa_plan_probes_only_sha2_and_honors_advertised_hash() {
            assert_eq!(
                rsa_hash_plan(None).unwrap(),
                [Some(HashAlg::Sha512), Some(HashAlg::Sha256)]
            );
            assert_eq!(
                rsa_hash_plan(Some(Some(HashAlg::Sha512))).unwrap(),
                [Some(HashAlg::Sha512)]
            );
            assert_eq!(
                rsa_hash_plan(Some(Some(HashAlg::Sha256))).unwrap(),
                [Some(HashAlg::Sha256)]
            );
            assert!(matches!(
                rsa_hash_plan(Some(None)),
                Err(AgentAuthFailure::RsaSha2Unsupported)
            ));
        }
    }
}

pub(crate) async fn authenticate(
    session: &mut Handle<SshHandler>,
    username: &str,
    auth: &AgentAuth,
    budget: Duration,
    stage: &str,
) -> Result<()> {
    #[cfg(unix)]
    {
        unix::authenticate(session, username, auth, budget, stage).await
    }
    #[cfg(not(unix))]
    {
        let _ = (session, username, auth, budget);
        Err(SshMcpError::config(format!(
            "{stage}: ssh-agent authentication requires a Unix-domain socket (not available on this platform)"
        )))
    }
}
