//! Agent authentication acceptance against the actual Docker sshd.
#![cfg(unix)]
use super::common::*;
#[path = "../support/spy_agent.rs"]
mod spy_agent;
use russh::keys::PrivateKey;
use spy_agent::{Behavior, SpyAgent, generate_key};
use ssh_mcp::AgentAuth;
use std::{path::Path, sync::Arc, time::Duration};

async fn fixture() -> (testcontainers::ContainerAsync<GenericImage>, String, u16) {
    init_test_env().expect("Docker SSH fixture is required");
    let container = GenericImage::new("ssh-mcp-debian-sshd", "latest")
        .with_exposed_port(2222u16.into())
        .start()
        .await
        .unwrap();
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(2222).await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    (container, host, port)
}
async fn authorize(
    container: &testcontainers::ContainerAsync<GenericImage>,
    user: &str,
    key: &PrivateKey,
) {
    let public = key.public_key().to_openssh().unwrap();
    let script = format!(
        "printf '%s\\n' '{}' >> /home/{user}/.ssh/authorized_keys",
        ssh_mcp::escape_for_shell(&public)
    );
    let output = tokio::process::Command::new("docker")
        .args(["exec", container.id(), "sh", "-c", &script])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn config(host: &str, port: u16, socket: &Path, key: Option<&PrivateKey>) -> Config {
    Config {
        host: host.into(),
        port,
        user: "test".into(),
        password: None,
        key: None,
        agent: Some(AgentAuth {
            socket: socket.into(),
            identity: key.map(|key| key.public_key().clone()),
        }),
        auth_timeout_ms: Some(3000),
        jump: None,
        su_password: None,
        sudo_password: None,
        timeout_ms: 30000,
        max_chars: Some(20000),
        max_output_tokens: Some(12000),
        disable_sudo: true,
        keepalive_interval: 30,
        keepalive_max: 3,
        reconnect_retries: 3,
        reconnect_backoff_ms: 20,
        health_probe_timeout_ms: 1500,
        strict_host_key_checking: ssh_mcp::HostKeyCheckMode::No,
        known_hosts: None,
    }
}
async fn command(server: &SshMcpServer, command: &str) -> String {
    let result = server.test_execute_command(command).await.unwrap();
    assert!(
        !result.is_error.unwrap_or(false),
        "{}",
        extract_text_from_result(&result)
    );
    extract_text_from_result(&result)
}
async fn failure(server: &SshMcpServer, expected: &str) {
    let result = server
        .test_execute_command("printf authenticated")
        .await
        .unwrap();
    let text = extract_text_from_result(&result);
    assert!(
        result.is_error.unwrap_or(false),
        "unexpected success: {text}"
    );
    assert!(text.contains(expected), "expected {expected:?}: {text}");
}

#[tokio::test]
async fn agent_only_shell_patch_jobs_and_connection_reuse() {
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let agent = SpyAgent::new(std::slice::from_ref(&key)).await;
    let server = SshMcpServer::new(config(&host, port, agent.socket(), None))
        .await
        .unwrap();
    assert_eq!(command(&server, "whoami").await.trim(), "test");
    let patch = "*** Begin Patch\n*** Add File: /home/test/agent-patch.txt\n+agent patch content\n*** End Patch";
    let result = server.test_apply_patch(patch).await.unwrap();
    assert!(
        !result.is_error.unwrap_or(false),
        "{}",
        extract_text_from_result(&result)
    );
    assert_eq!(
        command(&server, "cat /home/test/agent-patch.txt")
            .await
            .trim(),
        "agent patch content"
    );
    let job = server
        .test_execute_background_command("printf agent-job > /home/test/agent-job.txt")
        .await
        .unwrap();
    assert!(
        !job.is_error.unwrap_or(false),
        "{}",
        extract_text_from_result(&job)
    );
    for _ in 0..50 {
        if command(&server, "cat /home/test/agent-job.txt 2>/dev/null || true")
            .await
            .trim()
            == "agent-job"
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        command(&server, "cat /home/test/agent-job.txt")
            .await
            .trim(),
        "agent-job"
    );
    assert_eq!(
        agent.sign_count(),
        1,
        "healthy tools reuse authenticated SSH"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn identity_selection_and_zero_signature_failures() {
    let (container, host, port) = fixture().await;
    let allowed = generate_key("ed25519");
    let other = generate_key("ed25519");
    authorize(&container, "test", &allowed).await;
    let agent = SpyAgent::new(&[allowed.clone(), other.clone()]).await;
    let ambiguous = SshMcpServer::new(config(&host, port, agent.socket(), None))
        .await
        .unwrap();
    failure(&ambiguous, "identities").await;
    assert_eq!(agent.sign_count(), 0);
    ambiguous.shutdown().await;
    let missing = generate_key("ed25519");
    let server = SshMcpServer::new(config(&host, port, agent.socket(), Some(&missing)))
        .await
        .unwrap();
    failure(&server, "not loaded").await;
    assert_eq!(agent.sign_count(), 0);
    server.shutdown().await;
    let rejected = SshMcpServer::new(config(&host, port, agent.socket(), Some(&other)))
        .await
        .unwrap();
    failure(&rejected, "did not accept").await;
    assert_eq!(agent.sign_count(), 0);
    rejected.shutdown().await;
    let selected = SshMcpServer::new(config(&host, port, agent.socket(), Some(&allowed)))
        .await
        .unwrap();
    assert_eq!(command(&selected, "whoami").await.trim(), "test");
    assert_eq!(agent.sign_count(), 1);
    selected.shutdown().await;
    agent.load(&[]).await;
    let empty = SshMcpServer::new(config(&host, port, agent.socket(), None))
        .await
        .unwrap();
    failure(&empty, "no usable").await;
    assert_eq!(agent.sign_count(), 1);
    empty.shutdown().await;
}

#[tokio::test]
async fn strict_host_rejection_never_signs() {
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let agent = SpyAgent::new(&[key]).await;
    let directory = tempfile::tempdir().unwrap();
    let mut cfg = config(&host, port, agent.socket(), None);
    cfg.strict_host_key_checking = ssh_mcp::HostKeyCheckMode::Yes;
    cfg.known_hosts = Some(directory.path().join("known_hosts"));
    let server = SshMcpServer::new(cfg).await.unwrap();
    failure(&server, "host key").await;
    assert_eq!(agent.sign_count(), 0);
    assert_eq!(
        agent.connection_count(),
        1,
        "host verification precedes agent access"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn refusal_timeout_cancel_and_waiter_recover_without_signing_storms() {
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let agent = SpyAgent::new(&[key]).await;
    agent.set_behavior(Behavior::Refuse).await;
    let server = SshMcpServer::new(config(&host, port, agent.socket(), None))
        .await
        .unwrap();
    futures::future::join_all((0..4).map(|_| failure(&server, "refused"))).await;
    assert_eq!(agent.sign_count(), 1);
    server.shutdown().await;
    agent
        .set_behavior(Behavior::Delay(Duration::from_secs(5)))
        .await;
    let mut cfg = config(&host, port, agent.socket(), None);
    cfg.auth_timeout_ms = Some(500);
    let server = Arc::new(SshMcpServer::new(cfg).await.unwrap());
    let start = tokio::time::Instant::now();
    failure(&server, "timed out").await;
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(agent.sign_count(), 2);
    agent.set_behavior(Behavior::Hang).await;
    let owner_server = server.clone();
    let owner =
        tokio::spawn(async move { owner_server.test_execute_command("printf cancelled").await });
    agent.wait_for_signs(3).await;
    let waiter_server = server.clone();
    let waiter = tokio::spawn(async move {
        waiter_server
            .test_execute_command("printf recovered-waiter")
            .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    owner.abort();
    let _ = owner.await;
    agent.set_behavior(Behavior::Allow).await;
    let result = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("cancelled owner leaked guard")
        .unwrap()
        .unwrap();
    assert!(
        result.is_error.unwrap_or(false),
        "{}",
        extract_text_from_result(&result)
    );
    assert!(extract_text_from_result(&result).contains("cancelled"));
    assert_eq!(
        agent.sign_count(),
        3,
        "cancelled owner does not trigger waiter signing"
    );
    assert_eq!(command(&server, "printf fresh").await.trim(), "fresh");
    server.shutdown().await;
}

#[tokio::test]
async fn missing_socket_recovers_and_replacement_reopens_on_reconnect() {
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let server = SshMcpServer::new(config(&host, port, &socket, Some(&key)))
        .await
        .unwrap();
    failure(&server, "socket").await;
    let mut agent = SpyAgent::at(directory, socket, std::slice::from_ref(&key)).await;
    assert_eq!(command(&server, "printf first").await.trim(), "first");
    let connections = agent.connection_count();
    agent.replace_socket(&[key]).await;
    // Disconnect only the authenticated session, retaining the container's listening sshd.
    let result = server
        .test_execute_command("printf once >> /home/test/replay-marker; kill -KILL $PPID")
        .await
        .unwrap();
    let _ = result;
    assert_eq!(
        command(&server, "cat /home/test/replay-marker")
            .await
            .trim(),
        "once"
    );
    assert!(agent.connection_count() > connections);
    assert_eq!(agent.sign_count(), 2);
    server.shutdown().await;
}

#[tokio::test]
async fn supported_algorithms_authenticate_with_one_signature() {
    let (container, host, port) = fixture().await;
    for algorithm in ["ed25519", "ecdsa", "ecdsa384", "rsa"] {
        let key = generate_key(algorithm);
        authorize(&container, "test", &key).await;
        // russh 0.61.2's agent server ignores RSA signing flags and returns
        // legacy ssh-rsa. Exercise SHA2 with OpenSSH behind a counting proxy.
        let mut openssh = if algorithm == "rsa" {
            Some(
                OpenSshAgent::start()
                    .await
                    .expect("ssh-agent is required to verify RSA SHA2 authentication"),
            )
        } else {
            None
        };
        let proxy = if let Some(agent) = &openssh {
            let mut client = russh::keys::agent::client::AgentClient::connect_uds(&agent.socket)
                .await
                .unwrap();
            client.add_identity(&key, &[]).await.unwrap();
            Some(CountingAgentProxy::start(&agent.socket).await)
        } else {
            None
        };
        let spy = if proxy.is_none() {
            Some(SpyAgent::new(std::slice::from_ref(&key)).await)
        } else {
            None
        };
        let socket = proxy
            .as_ref()
            .map(|proxy| proxy.socket.as_path())
            .unwrap_or_else(|| spy.as_ref().unwrap().socket());
        let server = SshMcpServer::new(config(&host, port, socket, None))
            .await
            .unwrap_or_else(|error| panic!("{algorithm}: {error}"));
        let result = server
            .test_execute_command("whoami")
            .await
            .unwrap_or_else(|error| panic!("{algorithm}: {error}"));
        let text = extract_text_from_result(&result);
        assert!(!result.is_error.unwrap_or(false), "{algorithm}: {text}");
        assert_eq!(text.trim(), "test", "{algorithm}");
        if let Some(proxy) = &proxy {
            assert_eq!(proxy.sign_count(), 1, "{algorithm}");
            let flags = proxy.sign_flags.lock().await;
            assert!(
                matches!(flags.as_slice(), [2] | [4]),
                "RSA must request exactly one SHA2 signature, observed flags: {flags:?}"
            );
        } else {
            assert_eq!(spy.as_ref().unwrap().sign_count(), 1, "{algorithm}");
        }
        server.shutdown().await;
        if let Some(agent) = openssh.as_mut() {
            agent.child.kill().await.unwrap();
            agent.child.wait().await.unwrap();
        }
    }
}

#[tokio::test]
async fn rsa_sha1_only_server_is_rejected_without_signing() {
    init_test_env().expect("Docker SSH fixture is required");
    let container = GenericImage::new("ssh-mcp-debian-sshd", "latest")
        .with_exposed_port(2222u16.into())
        .with_cmd(["-p", "2222", "-o", "PubkeyAcceptedAlgorithms=ssh-rsa"])
        .start()
        .await
        .unwrap();
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(2222).await.unwrap();
    let key = generate_key("rsa");
    authorize(&container, "test", &key).await;
    let mut agent = OpenSshAgent::start()
        .await
        .expect("isolated OpenSSH agent required for RSA");
    let mut client = russh::keys::agent::client::AgentClient::connect_uds(&agent.socket)
        .await
        .unwrap();
    client.add_identity(&key, &[]).await.unwrap();
    let proxy = CountingAgentProxy::start(&agent.socket).await;
    let server = SshMcpServer::new(config(&host, port, &proxy.socket, Some(&key)))
        .await
        .unwrap();
    failure(&server, "does not support rsa-sha2").await;
    assert_eq!(
        proxy.sign_count(),
        0,
        "SHA-1 must never be offered for signing"
    );
    server.shutdown().await;
    agent.child.kill().await.unwrap();
    agent.child.wait().await.unwrap();
}

#[tokio::test]
async fn independent_target_jump_nine_authentication_combinations() {
    let (container, host, port) = fixture().await;
    let target_key = generate_key("ed25519");
    let jump_key = generate_key("ecdsa");
    authorize(&container, "test", &target_key).await;
    authorize(&container, "jump", &jump_key).await;
    let target_agent = SpyAgent::new(std::slice::from_ref(&target_key)).await;
    let jump_agent = SpyAgent::new(std::slice::from_ref(&jump_key)).await;
    let directory = tempfile::tempdir().unwrap();
    let target_file = directory.path().join("target");
    let jump_file = directory.path().join("jump");
    std::fs::write(
        &target_file,
        target_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    std::fs::write(
        &jump_file,
        jump_key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    for target in 0..3 {
        for jump in 0..3 {
            let before_target = target_agent.sign_count();
            let before_jump = jump_agent.sign_count();
            let mut cfg = config("127.0.0.1", 2222, target_agent.socket(), Some(&target_key));
            match target {
                0 => {
                    cfg.agent = None;
                    cfg.password = Some("secret".into());
                }
                1 => {
                    cfg.agent = None;
                    cfg.key = Some(target_file.clone());
                }
                _ => {}
            }
            cfg.jump = Some(JumpConfig {
                host: host.clone(),
                port,
                user: "jump".into(),
                password: (jump == 0).then(|| "jump-secret".into()),
                key: (jump == 1).then(|| jump_file.clone()),
                agent: (jump == 2).then(|| AgentAuth {
                    socket: jump_agent.socket().into(),
                    identity: Some(jump_key.public_key().clone()),
                }),
            });
            let server = SshMcpServer::new(cfg).await.unwrap();
            assert_eq!(
                command(&server, "whoami").await.trim(),
                "test",
                "target {target}, jump {jump}"
            );
            assert_eq!(
                target_agent.sign_count() - before_target,
                usize::from(target == 2)
            );
            assert_eq!(
                jump_agent.sign_count() - before_jump,
                usize::from(jump == 2)
            );
            server.shutdown().await;
        }
    }
}

#[tokio::test]
async fn transfers_roundtrip_file_directory_overwrite_and_external_rejection() {
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let agent = SpyAgent::new(&[key]).await;
    let server = SshMcpServer::new(config(&host, port, agent.socket(), None))
        .await
        .unwrap();
    let directory = local_tempdir();
    let file = directory.path().join("file");
    std::fs::write(&file, b"agent transfer\0binary\n").unwrap();
    for transport in [
        TransferTransport::Sftp,
        TransferTransport::Scp,
        TransferTransport::Rsync,
    ] {
        let response = server
            .test_transfer(TransferParams {
                operation: TransferOperation::Put,
                local_path: local_parameter(&file),
                remote_path: "/home/test/rejected-transfer".into(),
                transport,
                kind: Some(TransferKind::File),
                ..Default::default()
            })
            .await;
        assert!(!response.ok);
        assert!(response.error.unwrap().contains("not supported"));
        assert_eq!(
            command(
                &server,
                "test ! -e /home/test/rejected-transfer && printf untouched"
            )
            .await
            .trim(),
            "untouched"
        );
    }
    for kind in [TransferKind::File, TransferKind::Directory] {
        let (local, remote) = if kind == TransferKind::File {
            (file.clone(), "/home/test/rejected-transfer")
        } else {
            let tree = directory.path().join("tree");
            std::fs::create_dir_all(tree.join("nested")).unwrap();
            std::fs::write(tree.join("nested/payload"), b"directory payload").unwrap();
            (tree, "/home/test/agent-tree")
        };
        let put = TransferParams {
            operation: TransferOperation::Put,
            local_path: local_parameter(&local),
            remote_path: remote.into(),
            transport: TransferTransport::Auto,
            kind: Some(kind),
            overwrite: true,
            ..Default::default()
        };
        let response = server.test_transfer(put.clone()).await;
        assert!(response.ok, "{:?}", response.error);
        assert_eq!(response.transport_used, TransferTransport::ExecRaw);
        assert_eq!(response.fallback_chain, vec![TransferTransport::ExecRaw]);
        let mut conflict = put;
        conflict.overwrite = false;
        assert!(!server.test_transfer(conflict).await.ok);
        let destination = directory.path().join(if kind == TransferKind::File {
            "download"
        } else {
            "download-tree"
        });
        let get = server
            .test_transfer(TransferParams {
                operation: TransferOperation::Get,
                local_path: local_parameter(&destination),
                remote_path: remote.into(),
                transport: TransferTransport::ExecRaw,
                kind: Some(kind),
                overwrite: true,
                ..Default::default()
            })
            .await;
        assert!(get.ok, "{:?}", get.error);
        if kind == TransferKind::File {
            assert_eq!(
                std::fs::read(destination).unwrap(),
                b"agent transfer\0binary\n"
            );
        } else {
            assert_eq!(
                std::fs::read(destination.join("nested/payload")).unwrap(),
                b"directory payload"
            );
        }
    }
    server.shutdown().await;
}

struct McpProcess {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: tokio::io::BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}
impl McpProcess {
    async fn start(
        host: &str,
        port: u16,
        socket: &Path,
        spool: &Path,
        stderr: std::process::Stdio,
    ) -> Self {
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_ssh-mcp"))
            .args([
                "--host",
                host,
                "--port",
                &port.to_string(),
                "--user",
                "test",
                "--agent",
                "--agent-socket",
            ])
            .arg(socket)
            .args([
                "--strict-host-key-checking",
                "no",
                "--disable-sudo",
                "--spool-dir",
            ])
            .arg(spool)
            .env_remove("SSH_MCP_PASSWORD")
            .env_remove("SSH_MCP_KEY")
            .env("RUST_LOG", "trace")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(stderr)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut process = Self {
            child,
            input,
            output,
            next_id: 0,
        };
        process.rpc("initialize", serde_json::json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"agent-acceptance","version":"1"}})).await;
        process
            .send(serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        process
    }
    async fn send(&mut self, value: serde_json::Value) {
        use tokio::io::AsyncWriteExt;
        self.input
            .write_all(format!("{value}\n").as_bytes())
            .await
            .unwrap();
        self.input.flush().await.unwrap();
    }
    async fn rpc(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        use tokio::io::AsyncBufReadExt;
        self.next_id += 1;
        let id = self.next_id;
        self.send(serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut line = String::new();
                assert_ne!(
                    self.output.read_line(&mut line).await.unwrap(),
                    0,
                    "MCP exited"
                );
                let response: serde_json::Value =
                    serde_json::from_str(&line).expect("stdout must contain JSON-RPC only");
                if response["id"] == id {
                    assert!(response.get("error").is_none(), "{response}");
                    return response["result"].clone();
                }
            }
        })
        .await
        .expect("MCP request timed out")
    }
    async fn tool(&mut self, name: &str, arguments: serde_json::Value) -> serde_json::Value {
        let result = self
            .rpc(
                "tools/call",
                serde_json::json!({"name":name,"arguments":arguments}),
            )
            .await;
        assert_ne!(result["isError"], true, "{result}");
        result
    }
}
fn tool_text(result: &serde_json::Value) -> String {
    result["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|block| block["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}
fn tool_json(result: &serde_json::Value) -> serde_json::Value {
    serde_json::from_str(&tool_text(result)).expect("tool result is JSON")
}

#[tokio::test]
async fn four_genuine_stdio_processes_keep_jobs_and_spools_independent() {
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let agent = SpyAgent::new(&[key]).await;
    let directory = tempfile::tempdir().unwrap();
    let stderr_path = directory.path().join("trace.log");
    let starts = (0..4).map(|index| {
        let spool = directory.path().join(format!("spool-{index}"));
        std::fs::create_dir(&spool).unwrap();
        let stderr = if index == 0 {
            std::process::Stdio::from(std::fs::File::create(&stderr_path).unwrap())
        } else {
            std::process::Stdio::null()
        };
        let host = &host;
        let agent = &agent;
        async move { McpProcess::start(host, port, agent.socket(), &spool, stderr).await }
    });
    let mut clients = futures::future::join_all(starts).await;
    let calls = clients.iter_mut().enumerate().map(|(index, client)| async move {
        let patch_path = format!("/home/test/client-{index}-patch");
        client.tool("apply_patch", serde_json::json!({"patch":format!("*** Begin Patch\n*** Add File: {patch_path}\n+patch-{index}\n*** End Patch")})).await;
        let verified = client.tool("shell", serde_json::json!({"command":format!("cat {patch_path}")})).await;
        assert!(tool_text(&verified).contains(&format!("patch-{index}")));
        let local = local_tempdir(); let source = local.path().join("source"); let destination = local.path().join("download");
        let contents = format!("process-{index}-transfer"); std::fs::write(&source, contents.as_bytes()).unwrap();
        let remote = format!("/home/test/client-{index}-transfer");
        let put = client.tool("transfer", serde_json::json!({"operation":"put","local_path":local_parameter(&source),"remote_path":remote,"transport":"auto","kind":"file","overwrite":true})).await;
        let put = tool_json(&put); assert_eq!(put["ok"], true, "{put}"); assert_eq!(put["transport_used"], "exec-raw", "{put}");
        let get = client.tool("transfer", serde_json::json!({"operation":"get","local_path":local_parameter(&destination),"remote_path":remote,"transport":"exec-raw","kind":"file","overwrite":true})).await;
        assert_eq!(tool_json(&get)["ok"], true);
        assert_eq!(std::fs::read(destination).unwrap(), contents.as_bytes());
        let result = client.tool("shell", serde_json::json!({"command":format!("printf started-{index}; sleep 3; printf finished-{index}"),"background":true})).await;
        tool_json(&result)["job_id"].as_str().unwrap().to_string()
    });
    let jobs = futures::future::join_all(calls).await;
    assert_eq!(agent.sign_count(), 4);
    for left in 0..4 {
        for right in left + 1..4 {
            assert_ne!(jobs[left], jobs[right]);
        }
    }
    let exiting_job = clients[0]
        .tool(
            "check_process",
            serde_json::json!({"job_id":jobs[0],"tail_lines":10}),
        )
        .await;
    assert_eq!(
        tool_json(&exiting_job)["running"],
        true,
        "process must exit during its job"
    );
    clients[0].child.kill().await.unwrap();
    clients[0].child.wait().await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    for index in 1..4 {
        let result = clients[index]
            .tool(
                "check_process",
                serde_json::json!({"job_id":jobs[index],"tail_lines":50}),
            )
            .await;
        let status = tool_json(&result);
        assert_eq!(status["running"], false);
        assert_eq!(status["exit_code"], 0);
        assert!(
            status["log_tail"]
                .to_string()
                .contains(&format!("finished-{index}")),
            "{status}"
        );
        let log = status["log_path"].as_str().unwrap();
        assert!(
            Path::new(log).starts_with(directory.path().join(format!("spool-{index}"))),
            "{log}"
        );
        assert!(
            std::fs::read_to_string(log)
                .unwrap()
                .contains(&format!("finished-{index}"))
        );
        let output = clients[index]
            .tool(
                "shell",
                serde_json::json!({"command":format!("printf still-alive-{index}")}),
            )
            .await;
        assert!(tool_text(&output).contains(&format!("still-alive-{index}")));
    }
    let stderr = std::fs::read_to_string(stderr_path).unwrap();
    assert!(
        !stderr.contains("sign_request:"),
        "raw signing request leaked"
    );
    assert!(!stderr.contains("identities: ["), "raw agent frame leaked");
    for client in clients.iter_mut().skip(1) {
        client.child.kill().await.unwrap();
        client.child.wait().await.unwrap();
    }
}

struct OpenSshAgent {
    child: tokio::process::Child,
    directory: tempfile::TempDir,
    socket: std::path::PathBuf,
}
impl OpenSshAgent {
    async fn start() -> Option<Self> {
        if std::process::Command::new("ssh-agent")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("optional real OpenSSH agent test skipped: ssh-agent unavailable");
            return None;
        }
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("openssh.sock");
        let child = tokio::process::Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        Some(Self {
            child,
            directory,
            socket,
        })
    }
    async fn add(&self, args: &[&str]) -> std::process::Output {
        tokio::process::Command::new("ssh-add")
            .env("SSH_AUTH_SOCK", &self.socket)
            .args(args)
            .output()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn real_openssh_agent_plain_and_certificate_identities() {
    let Some(mut agent) = OpenSshAgent::start().await else {
        return;
    };
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let key_path = agent.directory.path().join("identity");
    std::fs::write(
        &key_path,
        key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
        key_path.with_extension("pub"),
        key.public_key().to_openssh().unwrap(),
    )
    .unwrap();
    let ca = agent.directory.path().join("ca");
    assert!(
        std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ca)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        std::process::Command::new("ssh-keygen")
            .args(["-q", "-s"])
            .arg(&ca)
            .args(["-I", "agent-acceptance", "-n", "test"])
            .arg(key_path.with_extension("pub"))
            .status()
            .unwrap()
            .success()
    );
    let path = key_path.to_str().unwrap();
    assert!(
        agent.add(&[path]).await.status.success(),
        "ssh-add should load certificate and plain identity"
    );
    let server = SshMcpServer::new(config(&host, port, &agent.socket, Some(&key)))
        .await
        .unwrap();
    assert_eq!(command(&server, "whoami").await.trim(), "test");
    server.shutdown().await;
    assert!(agent.add(&["-D"]).await.status.success());
    let cert_only = agent.add(&["-C", path]).await;
    if String::from_utf8_lossy(&cert_only.stderr).contains("illegal option") {
        eprintln!("optional cert-only loading skipped: ssh-add lacks -C");
    } else {
        // Some ssh-add versions return 1 after successfully adding only the cert.
        // Verify the actual loaded identities before exercising the endpoint.
        let mut client = russh::keys::agent::client::AgentClient::connect_uds(&agent.socket)
            .await
            .unwrap();
        let identities = client.request_identities().await.unwrap();
        assert!(
            !identities.is_empty(),
            "certificate was not loaded: {}",
            String::from_utf8_lossy(&cert_only.stderr)
        );
        assert!(identities.iter().all(|identity| matches!(
            identity,
            russh::keys::agent::AgentIdentity::Certificate { .. }
        )));
        let server = SshMcpServer::new(config(&host, port, &agent.socket, None))
            .await
            .unwrap();
        failure(&server, "no usable").await;
        server.shutdown().await;
    }
    agent.child.kill().await.unwrap();
    agent.child.wait().await.unwrap();
}

#[tokio::test]
async fn destination_constrained_real_agent_reports_refusal() {
    let Some(mut agent) = OpenSshAgent::start().await else {
        return;
    };
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let key_path = agent.directory.path().join("restricted");
    std::fs::write(
        &key_path,
        key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let scan = tokio::process::Command::new("ssh-keyscan")
        .args(["-p", &port.to_string(), &host])
        .output()
        .await
        .unwrap();
    assert!(scan.status.success());
    let known_hosts = agent.directory.path().join("known_hosts");
    std::fs::write(&known_hosts, &scan.stdout).unwrap();
    let constraint = format!("test@[{host}]:{port}");
    let output = agent
        .add(&[
            "-H",
            known_hosts.to_str().unwrap(),
            "-h",
            &constraint,
            key_path.to_str().unwrap(),
        ])
        .await;
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("illegal option")
    {
        eprintln!("optional destination constraints skipped: local ssh-add lacks -h");
    } else {
        assert!(
            output.status.success(),
            "constraint loading failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let server = SshMcpServer::new(config(&host, port, &agent.socket, Some(&key)))
            .await
            .unwrap();
        failure(&server, "refused").await;
        server.shutdown().await;
    }
    agent.child.kill().await.unwrap();
    agent.child.wait().await.unwrap();
}

#[tokio::test]
async fn background_transfer_timeout_and_cancel_preserve_destination_and_release_reservation() {
    let (container, host, port) = fixture().await;
    let key = generate_key("ed25519");
    authorize(&container, "test", &key).await;
    let agent = SpyAgent::new(&[key]).await;
    let server = Arc::new(
        SshMcpServer::new(config(&host, port, agent.socket(), None))
            .await
            .unwrap(),
    );
    let directory = local_tempdir();
    let tree = directory.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("payload"), b"cancelled replacement").unwrap();
    // Exceed the SSH receive window so cancellation also stops a blocked encoder.
    std::fs::File::create(tree.join("large-payload"))
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    command(
        &server,
        "mkdir /home/test/controlled-tree; printf original > /home/test/controlled-tree/payload",
    )
    .await;
    // A gate in the real remote tar command provides observable in-flight I/O.
    // It supplies no transfer effects; after release the production tar receives the stream.
    let script = "mv /bin/tar /bin/tar.real; printf '%s\\n' '#!/bin/sh' 'printf %s \"$$\" > /tmp/agent-tar-pid' 'touch /tmp/agent-tar-entered' 'while [ ! -e /tmp/agent-tar-release ]; do sleep 0.05; done' 'exec /bin/tar.real \"$@\"' > /bin/tar; chmod 755 /bin/tar";
    let output = tokio::process::Command::new("docker")
        .args(["exec", container.id(), "sh", "-c", script])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let params = TransferParams {
        operation: TransferOperation::Put,
        local_path: local_parameter(&tree),
        remote_path: "/home/test/controlled-tree".into(),
        kind: Some(TransferKind::Directory),
        transport: TransferTransport::ExecRaw,
        overwrite: true,
        timeout_ms: Some(1500),
        ..Default::default()
    };
    let started = server
        .test_background_transfer(params.clone())
        .await
        .unwrap();
    assert!(
        !started.is_error.unwrap_or(false),
        "{}",
        extract_text_from_result(&started)
    );
    let start: serde_json::Value =
        serde_json::from_str(&extract_text_from_result(&started)).unwrap();
    let id = start["job_id"].as_str().unwrap();
    let mut terminal = None;
    for _ in 0..100 {
        let result = server.test_check_process(id, 50).await.unwrap();
        let status: serde_json::Value =
            serde_json::from_str(&extract_text_from_result(&result)).unwrap();
        if status["running"] == false {
            terminal = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = terminal.expect("background transfer did not reach terminal timeout");
    assert_eq!(status["result"]["ok"], false, "{status}");
    assert!(
        status["result"]["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("timeout"),
        "{status}"
    );
    assert_eq!(
        command(
            &server,
            "test -e /tmp/agent-tar-entered && cat /home/test/controlled-tree/payload"
        )
        .await
        .trim(),
        "original"
    );
    let leftovers = command(
        &server,
        "if kill -0 \"$(cat /tmp/agent-tar-pid)\" 2>/dev/null; then printf 'writer-alive\\n'; fi; find /home/test -maxdepth 1 -name '*ssh-mcp*' -print",
    )
    .await;
    assert!(
        leftovers.trim().is_empty(),
        "timeout left an owned writer or staging artifacts: {leftovers}"
    );
    command(&server, "rm /tmp/agent-tar-entered").await;
    let token = tokio_util::sync::CancellationToken::new();
    let task_token = token.clone();
    let task_server = server.clone();
    let mut cancelled_params = params.clone();
    cancelled_params.timeout_ms = Some(30000);
    let transfer = tokio::spawn(async move {
        task_server
            .test_transfer_with_cancellation(cancelled_params, task_token)
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if command(
                &server,
                "test -e /tmp/agent-tar-entered && printf entered || true",
            )
            .await
            .trim()
                == "entered"
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("cancelled transfer never entered raw tar stream");
    token.cancel();
    let cancelled = tokio::time::timeout(Duration::from_secs(10), transfer)
        .await
        .unwrap()
        .unwrap();
    assert!(!cancelled.ok);
    assert!(cancelled.error.unwrap().to_lowercase().contains("cancel"));
    assert_eq!(
        command(&server, "cat /home/test/controlled-tree/payload")
            .await
            .trim(),
        "original"
    );
    let leftovers = command(
        &server,
        "if kill -0 \"$(cat /tmp/agent-tar-pid)\" 2>/dev/null; then printf 'writer-alive\\n'; fi; find /home/test -maxdepth 1 -name '*ssh-mcp*' -print",
    )
    .await;
    assert!(
        leftovers.trim().is_empty(),
        "cancel left an owned writer or staging artifacts: {leftovers}"
    );
    command(&server, "touch /tmp/agent-tar-release").await;
    assert_eq!(
        command(&server, "cat /home/test/controlled-tree/payload")
            .await
            .trim(),
        "original",
        "cancelled upload committed after gate release"
    );
    std::fs::write(tree.join("payload"), b"successful replacement").unwrap();
    let mut retry = params;
    retry.timeout_ms = Some(30000);
    let completed = server.test_transfer(retry.clone()).await;
    assert!(
        completed.ok,
        "cancel/timeout leaked reservation: {:?}",
        completed.error
    );
    assert_eq!(
        command(&server, "cat /home/test/controlled-tree/payload")
            .await
            .trim(),
        "successful replacement"
    );
    retry.remote_path = "/home/test/background-completed-tree".into();
    let started = server.test_background_transfer(retry).await.unwrap();
    assert!(!started.is_error.unwrap_or(false));
    let started: serde_json::Value =
        serde_json::from_str(&extract_text_from_result(&started)).unwrap();
    let mut successful = None;
    for _ in 0..100 {
        let result = server
            .test_check_process(started["job_id"].as_str().unwrap(), 50)
            .await
            .unwrap();
        let status: serde_json::Value =
            serde_json::from_str(&extract_text_from_result(&result)).unwrap();
        if status["running"] == false {
            successful = Some(status);
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let successful = successful.expect("background success never completed");
    assert_eq!(successful["result"]["ok"], true, "{successful}");
    assert_eq!(
        command(&server, "cat /home/test/background-completed-tree/payload")
            .await
            .trim(),
        "successful replacement"
    );
    let artifacts = command(
        &server,
        "find /home/test -maxdepth 1 -name '*ssh-mcp*' -print",
    )
    .await;
    assert!(
        artifacts.trim().is_empty(),
        "staging artifacts leaked: {artifacts}"
    );
    server.shutdown().await;
}

fn local_tempdir() -> tempfile::TempDir {
    let parent = std::env::current_dir().unwrap().join("target/tmp");
    std::fs::create_dir_all(&parent).unwrap();
    tempfile::tempdir_in(parent).unwrap()
}
fn local_parameter(path: &Path) -> String {
    path.strip_prefix(std::env::current_dir().unwrap())
        .unwrap()
        .display()
        .to_string()
}

/// Counts real agent signing requests while forwarding unchanged protocol frames.
struct CountingAgentProxy {
    _directory: tempfile::TempDir,
    socket: std::path::PathBuf,
    signs: Arc<std::sync::atomic::AtomicUsize>,
    sign_flags: Arc<tokio::sync::Mutex<Vec<u32>>>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingAgentProxy {
    async fn start(upstream: &Path) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("counting-agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let upstream = upstream.to_path_buf();
        let signs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let sign_flags = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let request_count = signs.clone();
        let request_flags = sign_flags.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (client, _) = accepted.unwrap();
                        let agent = tokio::net::UnixStream::connect(&upstream).await.unwrap();
                        let (mut from_client, mut to_client) = client.into_split();
                        let (mut from_agent, mut to_agent) = agent.into_split();
                        let signs = request_count.clone();
                        let flags = request_flags.clone();
                        connections.spawn(async move {
                            let requests = async move {
                                loop {
                                    let mut header = [0; 4];
                                    match from_client.read_exact(&mut header).await {
                                        Ok(_) => {}
                                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                                        Err(error) => return Err(error),
                                    }
                                    let mut frame = vec![0; u32::from_be_bytes(header) as usize];
                                    from_client.read_exact(&mut frame).await?;
                                    if frame.first() == Some(&13) {
                                        // SSH_AGENTC_SIGN_REQUEST ends with its u32 flags.
                                        let offset = frame.len() - 4;
                                        flags.lock().await.push(u32::from_be_bytes(
                                            frame[offset..].try_into().unwrap(),
                                        ));
                                        signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    }
                                    to_agent.write_all(&header).await?;
                                    to_agent.write_all(&frame).await?;
                                }
                                Ok::<_, std::io::Error>(())
                            };
                            let responses = tokio::io::copy(&mut from_agent, &mut to_client);
                            tokio::try_join!(requests, responses).map(|_| ())
                        });
                    }
                    finished = connections.join_next(), if !connections.is_empty() => {
                        finished.unwrap().unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            _directory: directory,
            socket,
            signs,
            sign_flags,
            task,
        }
    }

    fn sign_count(&self) -> usize {
        self.signs.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for CountingAgentProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}
