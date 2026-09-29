//! Isolated agent using russh's real agent protocol and signing implementation.
#![allow(dead_code)]
use futures::Stream;
use russh::keys::{
    PrivateKey,
    agent::{
        client::AgentClient,
        server::{Agent, MessageType, serve},
    },
};
use std::{
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Mutex,
    task::JoinHandle,
};

#[derive(Clone, Copy, Debug)]
pub enum Behavior {
    Allow,
    Refuse,
    Delay(Duration),
    Hang,
}
#[derive(Clone)]
struct Policy {
    behavior: Arc<Mutex<Behavior>>,
    signs: Arc<AtomicUsize>,
}
impl Agent for Policy {
    async fn confirm_request(&self, msg: MessageType) -> bool {
        if !matches!(msg, MessageType::Sign) {
            return true;
        }
        self.signs.fetch_add(1, Ordering::SeqCst);
        let behavior = *self.behavior.lock().await;
        match behavior {
            Behavior::Allow => true,
            Behavior::Refuse => false,
            Behavior::Delay(delay) => {
                tokio::time::sleep(delay).await;
                true
            }
            Behavior::Hang => std::future::pending().await,
        }
    }
}
struct Listener {
    listener: UnixListener,
    connections: Arc<AtomicUsize>,
}
impl Stream for Listener {
    type Item = std::io::Result<UnixStream>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.listener.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => {
                self.connections.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Some(Ok(stream)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}
pub struct SpyAgent {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    policy: Policy,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl SpyAgent {
    pub async fn new(keys: &[PrivateKey]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("agent.sock");
        Self::at(directory, socket, keys).await
    }
    pub async fn at(directory: tempfile::TempDir, socket: PathBuf, keys: &[PrivateKey]) -> Self {
        let policy = Policy {
            behavior: Arc::new(Mutex::new(Behavior::Allow)),
            signs: Arc::new(AtomicUsize::new(0)),
        };
        let connections = Arc::new(AtomicUsize::new(0));
        let listener = Listener {
            listener: UnixListener::bind(&socket).unwrap(),
            connections: connections.clone(),
        };
        let server_policy = policy.clone();
        let task = tokio::spawn(async move {
            serve(listener, server_policy).await.unwrap();
        });
        let agent = Self {
            _directory: directory,
            socket,
            policy,
            connections,
            task,
        };
        agent.load(keys).await;
        agent
    }
    pub fn socket(&self) -> &Path {
        &self.socket
    }
    pub fn sign_count(&self) -> usize {
        self.policy.signs.load(Ordering::SeqCst)
    }
    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
    pub async fn set_behavior(&self, behavior: Behavior) {
        *self.policy.behavior.lock().await = behavior;
    }
    pub async fn load(&self, keys: &[PrivateKey]) {
        let mut client = AgentClient::connect_uds(&self.socket).await.unwrap();
        // russh 0.61.2's remove_all_identities leaves the frame length at zero.
        // Its individual remove operation correctly frames the protocol request.
        for identity in client.request_identities().await.unwrap() {
            client
                .remove_identity(&identity.public_key())
                .await
                .unwrap();
        }
        for key in keys {
            client.add_identity(key, &[]).await.unwrap();
        }
    }
    pub async fn replace_socket(&mut self, keys: &[PrivateKey]) {
        self.task.abort();
        std::fs::remove_file(&self.socket).unwrap();
        let listener = Listener {
            listener: UnixListener::bind(&self.socket).unwrap(),
            connections: self.connections.clone(),
        };
        let policy = self.policy.clone();
        self.task = tokio::spawn(async move {
            serve(listener, policy).await.unwrap();
        });
        self.load(keys).await;
    }
    pub async fn wait_for_signs(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.sign_count() < count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("agent never received expected signing request");
    }
}
impl Drop for SpyAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn generate_key(algorithm: &str) -> PrivateKey {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("key");
    let mut command = std::process::Command::new("ssh-keygen");
    command
        .args([
            "-q",
            "-t",
            if algorithm == "ecdsa384" {
                "ecdsa"
            } else {
                algorithm
            },
            "-N",
            "",
            "-f",
        ])
        .arg(&path);
    if algorithm == "rsa" {
        command.args(["-b", "2048"]);
    }
    if algorithm == "ecdsa384" {
        command.args(["-b", "384"]);
    }
    assert!(
        command
            .status()
            .expect("ssh-keygen is required for agent integration tests")
            .success()
    );
    russh::keys::load_secret_key(path, None).unwrap()
}
