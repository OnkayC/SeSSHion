//! One-hop SSH jump-host integration tests.
#![cfg(unix)]

use super::common::*;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_local_file(label: &str, contents: &str) -> (PathBuf, String) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let directory = PathBuf::from("target/tmp").join(format!("jump-{label}-{unique}"));
    std::fs::create_dir_all(&directory).expect("create local jump test directory");
    let file = directory.join("payload.txt");
    std::fs::write(&file, contents).expect("write jump test payload");
    (directory, file.to_string_lossy().into_owned())
}

async fn start_container() -> (testcontainers::ContainerAsync<GenericImage>, String, u16) {
    init_test_env().expect("Failed to initialize test environment");
    let container = GenericImage::new("ssh-mcp-debian-sshd", "latest")
        .with_exposed_port(2222u16.into())
        .start()
        .await
        .expect("Failed to start SSH container");
    let host = container
        .get_host()
        .await
        .expect("Failed to get container host")
        .to_string();
    let port = container
        .get_host_port_ipv4(2222)
        .await
        .expect("Failed to get mapped SSH port");
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    (container, host, port)
}

fn target_config(key_path: PathBuf, jump: JumpConfig) -> Config {
    Config {
        proxy_command: None,
        agent: None,
        auth_timeout_ms: None,
        host: "127.0.0.1".to_string(),
        port: 2222,
        user: "test".to_string(),
        password: None,
        key: Some(key_path),
        jump: Some(jump),
        su_password: None,
        sudo_password: None,
        timeout_ms: 30_000,
        max_chars: Some(1_000),
        max_output_tokens: Some(12_000),
        disable_sudo: true,
        keepalive_interval: 30,
        keepalive_max: 3,
        reconnect_retries: 1,
        reconnect_backoff_ms: 250,
        health_probe_timeout_ms: 1_500,
        strict_host_key_checking: ssh_mcp::HostKeyCheckMode::No,
        known_hosts: None,
    }
}

#[tokio::test]
async fn key_jump_routes_command_and_sftp_with_distinct_keys() {
    if !check_sftp() {
        tracing::warn!("skipping: local 'sftp' unavailable");
        return;
    }
    let (_container, jump_host, jump_port) = start_container().await;
    let (_target_key_dir, target_key) = setup_test_key();
    let (_jump_key_dir, jump_key) = setup_jump_test_key();
    let config = target_config(
        target_key,
        JumpConfig {
            agent: None,
            host: jump_host,
            port: jump_port,
            user: "jump".to_string(),
            password: None,
            key: Some(jump_key),
        },
    );
    let server = SshMcpServer::new(config)
        .await
        .expect("create jumped SSH server");

    let whoami = server
        .test_execute_command("whoami")
        .await
        .expect("execute command through jump");
    assert_eq!(extract_text_from_result(&whoami).trim(), "test");

    let (local_dir, local_path) = unique_local_file("key", "through jump\n");
    let remote_path = "/home/test/jump-key-transfer.txt".to_string();
    let response = server
        .test_transfer(TransferParams {
            operation: TransferOperation::Put,
            local_path,
            remote_path: remote_path.clone(),
            transport: TransferTransport::Sftp,
            kind: Some(TransferKind::File),
            overwrite: true,
            timeout_ms: Some(30_000),
            ..Default::default()
        })
        .await;
    assert!(response.ok, "jump SFTP failed: {:?}", response.error);

    let verify = server
        .test_execute_command(&format!("cat -- '{}'", remote_path))
        .await
        .expect("verify jumped transfer");
    assert!(extract_text_from_result(&verify).contains("through jump"));
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(local_dir);
}

#[tokio::test]
async fn password_jump_uses_exec_raw_and_rejects_explicit_sftp() {
    let (_container, jump_host, jump_port) = start_container().await;
    let (_target_key_dir, target_key) = setup_test_key();
    let config = target_config(
        target_key,
        JumpConfig {
            agent: None,
            host: jump_host,
            port: jump_port,
            user: "jump".to_string(),
            password: Some("jump-secret".to_string()),
            key: None,
        },
    );
    let server = SshMcpServer::new(config)
        .await
        .expect("create password-jumped SSH server");

    let whoami = server
        .test_execute_command("whoami")
        .await
        .expect("execute command through password jump");
    assert_eq!(extract_text_from_result(&whoami).trim(), "test");

    let (local_dir, local_path) = unique_local_file("password", "password jump\n");
    let auto = server
        .test_transfer(TransferParams {
            operation: TransferOperation::Put,
            local_path: local_path.clone(),
            remote_path: "/home/test/jump-password-auto.txt".to_string(),
            transport: TransferTransport::Auto,
            kind: Some(TransferKind::File),
            overwrite: true,
            timeout_ms: Some(30_000),
            ..Default::default()
        })
        .await;
    assert!(auto.ok, "jump auto transfer failed: {:?}", auto.error);
    assert_eq!(auto.transport_used, TransferTransport::ExecRaw);

    let explicit = server
        .test_transfer(TransferParams {
            operation: TransferOperation::Put,
            local_path,
            remote_path: "/home/test/jump-password-sftp.txt".to_string(),
            transport: TransferTransport::Sftp,
            kind: Some(TransferKind::File),
            overwrite: true,
            timeout_ms: Some(30_000),
            ..Default::default()
        })
        .await;
    assert!(!explicit.ok);
    assert!(
        explicit
            .error
            .as_deref()
            .is_some_and(|error| error.contains("jump host key required")),
        "unexpected explicit SFTP error: {:?}",
        explicit.error
    );

    server.shutdown().await;
    let _ = std::fs::remove_dir_all(local_dir);
}

#[tokio::test]
async fn explicit_proxy_routes_native_and_legacy_transfers_preserving_literal_percent() {
    if !check_openssh_client("ssh") || !check_sftp() || !check_scp() || !check_rsync() {
        tracing::warn!("skipping: local OpenSSH or rsync unavailable");
        return;
    }
    let (_container, jump_host, jump_port) = start_container().await;
    let (_target_key_dir, target_key) = setup_test_key();
    let (_jump_key_dir, jump_key) = setup_jump_test_key();
    let local_dir = tempfile::Builder::new()
        .prefix("proxy route's ")
        .tempdir()
        .expect("create proxy test directory");
    let recorder = local_dir.path().join("route.log");
    let quote = |value: &str| format!("'{}'", ssh_mcp::escape_for_shell(value));
    let mut config = target_config(
        target_key,
        JumpConfig {
            agent: None,
            host: jump_host.clone(),
            port: jump_port,
            user: "jump".to_string(),
            password: None,
            key: Some(jump_key.clone()),
        },
    );
    config.jump = None;
    // The target is reachable only through the container's forwarding SSH login.
    // Recording a literal %h detects a second, unintended token expansion by OpenSSH.
    config.proxy_command = Some(format!(
        r#"printf '%%s\n' %h %p %r '%%h' >> {}; exec ssh -i {} -p {} -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -W %h:%p {}"#,
        quote(&recorder.to_string_lossy()),
        quote(&jump_key.to_string_lossy()),
        jump_port,
        quote(&format!("jump@{jump_host}")),
    ));
    let server = SshMcpServer::new(config)
        .await
        .expect("create SSH server through explicit proxy");
    let whoami = server
        .test_execute_command("whoami")
        .await
        .expect("execute native command through proxy");
    assert_eq!(extract_text_from_result(&whoami).trim(), "test");
    assert_eq!(
        std::fs::read_to_string(&recorder).expect("native proxy invocation"),
        "127.0.0.1\n2222\ntest\n%h\n"
    );

    let payload = b"proxy transfer payload\n";
    let source = local_dir.path().join("source.txt");
    std::fs::write(&source, payload).expect("write transfer source");
    for (index, transport) in [
        TransferTransport::ExecRaw,
        TransferTransport::Sftp,
        TransferTransport::Scp,
        TransferTransport::Rsync,
    ]
    .into_iter()
    .enumerate()
    {
        let remote_path = format!("/home/test/explicit-proxy-{index}.txt");
        let destination = local_dir.path().join(format!("download-{index}.txt"));
        for (operation, local_path) in [
            (TransferOperation::Put, &source),
            (TransferOperation::Get, &destination),
        ] {
            std::fs::write(&recorder, "").expect("clear proxy invocation recorder");
            let response = server
                .test_transfer(TransferParams {
                    operation,
                    local_path: local_path.to_string_lossy().into_owned(),
                    remote_path: remote_path.clone(),
                    transport,
                    kind: Some(TransferKind::File),
                    overwrite: true,
                    timeout_ms: Some(30_000),
                    ..Default::default()
                })
                .await;
            assert!(
                response.ok,
                "{transport:?} {operation:?} through proxy failed: {:?}",
                response.error
            );
            assert_eq!(response.transport_used, transport);
            if transport != TransferTransport::ExecRaw {
                let recorded = std::fs::read_to_string(&recorder).expect("legacy proxy invocation");
                assert_eq!(
                    recorded.lines().take(4).collect::<Vec<_>>(),
                    ["127.0.0.1", "2222", "test", "%h"],
                    "proxy substitutions for {transport:?} {operation:?}"
                );
            }
        }
        assert_eq!(
            std::fs::read(&destination).expect("read transferred payload"),
            payload,
            "round-trip payload through {transport:?}"
        );
    }
    server.shutdown().await;
}
