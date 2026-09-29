#![cfg(unix)]
//! Physical hardware smoke: never opens a user's agent without all explicit opt-ins.
use ssh_mcp::{AgentAuth, HostKeyCheckMode, SshConfig, SshConnectionManager};
use std::{path::PathBuf, time::Duration};

#[tokio::test]
#[ignore = "requires SSH_MCP_YUBIKEY_TEST=1, SSH_MCP_YUBIKEY_PUB, SSH_MCP_YUBIKEY_HOST and user-managed hardware"]
async fn yubikey_selector_command_and_reconnect() {
    assert_eq!(
        std::env::var("SSH_MCP_YUBIKEY_TEST").as_deref(),
        Ok("1"),
        "explicit hardware opt-in required"
    );
    let public_path =
        std::env::var_os("SSH_MCP_YUBIKEY_PUB").expect("SSH_MCP_YUBIKEY_PUB required");
    let endpoint = std::env::var("SSH_MCP_YUBIKEY_HOST").expect("SSH_MCP_YUBIKEY_HOST required");
    let (user, host) = endpoint
        .split_once('@')
        .expect("SSH_MCP_YUBIKEY_HOST must be user@host");
    let socket = std::env::var_os("SSH_AUTH_SOCK").expect("user-managed SSH_AUTH_SOCK required");
    let public =
        russh::keys::PublicKey::from_openssh(&std::fs::read_to_string(public_path).unwrap())
            .unwrap();
    let mut config = SshConfig::new(host, user)
        .with_agent(AgentAuth {
            socket: PathBuf::from(socket),
            identity: Some(public),
        })
        .with_auth_timeout(Duration::from_secs(90));
    config.host_key_checking = HostKeyCheckMode::Yes;
    config.known_hosts = Some(
        PathBuf::from(std::env::var_os("HOME").expect("HOME required")).join(".ssh/known_hosts"),
    );
    let connection = SshConnectionManager::new(config).await;
    connection
        .connect()
        .await
        .expect("complete the configured PIN/touch policy");
    let output = connection
        .exec_command("printf yubikey-authenticated", Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(output.stdout, "yubikey-authenticated");
    connection
        .reconnect()
        .await
        .expect("fresh authentication after disconnect");
    assert_eq!(
        connection
            .exec_command("printf yubikey-reconnected", Duration::from_secs(10))
            .await
            .unwrap()
            .stdout,
        "yubikey-reconnected"
    );
    connection.close().await;
}
