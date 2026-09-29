//! Configuration and CLI argument parsing for SeSSHion

use clap::Parser;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Result, SshMcpError};
use crate::ssh::{AgentAuth, HostKeyCheckMode};

/// Default timeout for command execution in milliseconds
pub const DEFAULT_TIMEOUT_MS: u64 = 300_000; // 300 seconds

/// Default max characters for command length (None = unlimited)
pub const DEFAULT_MAX_CHARS: Option<usize> = Some(64_000);

/// Connection timeout in seconds
pub const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Number of reconnect retries after the initial attempt
pub const DEFAULT_RECONNECT_RETRIES: u64 = 3;

/// Base reconnect backoff in milliseconds
pub const DEFAULT_RECONNECT_BACKOFF_MS: u64 = 250;

/// Health probe timeout in milliseconds
pub const DEFAULT_HEALTH_PROBE_TIMEOUT_MS: u64 = 1500;

/// Maximum reconnect retries allowed by configuration
pub const MAX_RECONNECT_RETRIES: u64 = 10;

/// Minimum reconnect backoff in milliseconds
pub const MIN_RECONNECT_BACKOFF_MS: u64 = 10;

/// Maximum reconnect backoff in milliseconds
pub const MAX_RECONNECT_BACKOFF_MS: u64 = 30_000;

/// Minimum health probe timeout in milliseconds
pub const MIN_HEALTH_PROBE_TIMEOUT_MS: u64 = 100;

/// Maximum health probe timeout in milliseconds
pub const MAX_HEALTH_PROBE_TIMEOUT_MS: u64 = 30_000;

/// SeSSHion CLI arguments
#[derive(Parser, Debug, Clone)]
#[command(name = "ssh-mcp")]
#[command(author = "0FL01")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
pub struct Args {
    /// SSH host to connect to
    #[arg(long, env = "SSH_MCP_HOST")]
    pub host: String,

    /// SSH port
    #[arg(long, default_value = "22", env = "SSH_MCP_PORT")]
    pub port: u16,

    /// SSH username
    #[arg(long, env = "SSH_MCP_USER")]
    pub user: String,

    /// SSH password (alternative to key)
    #[arg(long, env = "SSH_MCP_PASSWORD")]
    pub password: Option<String>,

    /// Path to SSH private key file (alternative to password)
    #[arg(long, env = "SSH_MCP_KEY")]
    pub key: Option<PathBuf>,

    /// Authenticate exclusively through an SSH agent.
    #[arg(long, default_value = "false", env = "SSH_MCP_AGENT")]
    pub agent: bool,
    /// Override the snapshotted SSH_AUTH_SOCK path.
    #[arg(long, env = "SSH_MCP_AGENT_SOCKET")]
    pub agent_socket: Option<PathBuf>,
    /// Select a public key (.pub) loaded in the agent.
    #[arg(long, env = "SSH_MCP_AGENT_IDENTITY")]
    pub agent_identity: Option<PathBuf>,
    /// Per-endpoint authentication budget in milliseconds (1..=600000).
    #[arg(long, env = "SSH_MCP_AUTH_TIMEOUT_MS")]
    pub auth_timeout_ms: Option<u64>,

    /// SSH jump host in USER@HOST[:PORT] form
    #[arg(long, env = "SSH_MCP_JUMP")]
    pub jump: Option<String>,

    /// Path to the jump host SSH private key file
    #[arg(long, env = "SSH_MCP_JUMP_KEY")]
    pub jump_key: Option<PathBuf>,

    /// SSH login password for the jump host
    #[arg(long, env = "SSH_MCP_JUMP_PASSWORD")]
    pub jump_password: Option<String>,

    /// Authenticate the jump host exclusively through an SSH agent.
    #[arg(long, default_value = "false", env = "SSH_MCP_JUMP_AGENT")]
    pub jump_agent: bool,
    #[arg(long, env = "SSH_MCP_JUMP_AGENT_SOCKET")]
    pub jump_agent_socket: Option<PathBuf>,
    #[arg(long, env = "SSH_MCP_JUMP_AGENT_IDENTITY")]
    pub jump_agent_identity: Option<PathBuf>,

    /// Absolute local directory for background job logs and state
    #[arg(long, env = "SSH_MCP_SPOOL_DIR")]
    pub spool_dir: Option<PathBuf>,

    /// Password for `su` elevation
    #[arg(long, env = "SSH_MCP_SU_PASSWORD")]
    pub su_password: Option<String>,

    /// Password for `sudo` commands (if different from su_password)
    #[arg(long, env = "SSH_MCP_SUDO_PASSWORD")]
    pub sudo_password: Option<String>,

    /// Command execution timeout in milliseconds
    #[arg(long, default_value = "300000", env = "SSH_MCP_TIMEOUT")]
    pub timeout: u64,

    /// Maximum characters for command length.
    /// Use "none", "0", or negative value to disable limit.
    /// Default: 64000
    #[arg(long = "maxChars", env = "SSH_MCP_MAX_CHARS")]
    pub max_chars: Option<String>,

    /// Disable the sudo_shell and sudo_apply_patch tools
    #[arg(long, default_value = "false", env = "SSH_MCP_DISABLE_SUDO")]
    pub disable_sudo: bool,

    /// Maximum output tokens for command execution.
    /// Use "none" or "0" to disable limit.
    /// Supports "k" suffix (e.g., "16k" for 16000).
    /// Default: 16000 (approximately 64KB)
    #[arg(long = "max-output-tokens", env = "SSH_MCP_MAX_OUTPUT_TOKENS")]
    pub max_output_tokens: Option<String>,

    /// Logging level: trace, debug, info, warn, error
    #[arg(long, default_value = "info", env = "SSH_MCP_LOG_LEVEL", value_parser = clap::builder::PossibleValuesParser::new(["trace", "debug", "info", "warn", "error"]))]
    pub log_level: String,

    /// Log file path (default: stdout only)
    #[arg(long, env = "SSH_MCP_LOG_FILE")]
    pub log_file: Option<PathBuf>,

    /// Log format: text or json
    #[arg(long, default_value = "text", env = "SSH_MCP_LOG_FORMAT", value_parser = clap::builder::PossibleValuesParser::new(["text", "json"]))]
    pub log_format: String,

    /// Log rotation strategy: daily, hourly, never
    #[arg(long, default_value = "daily", env = "SSH_MCP_LOG_ROTATION", value_parser = clap::builder::PossibleValuesParser::new(["daily", "hourly", "never"]))]
    pub log_rotation: String,

    /// Keepalive interval in seconds (default: 30)
    /// Sends keepalive packets to maintain connection like a human user
    #[arg(long, default_value = "30", env = "SSH_MCP_KEEPALIVE_INTERVAL")]
    pub keepalive_interval: u64,

    /// Maximum keepalive failures before disconnecting (default: 3)
    /// Total idle timeout = keepalive_interval * keepalive_max
    #[arg(long, default_value = "3", env = "SSH_MCP_KEEPALIVE_MAX")]
    pub keepalive_max: u64,

    /// Number of reconnect retries after the initial attempt (default: 3)
    #[arg(long, default_value = "3", env = "SSH_MCP_RECONNECT_RETRIES")]
    pub reconnect_retries: u64,

    /// Base reconnect backoff in milliseconds (default: 250)
    #[arg(long, default_value = "250", env = "SSH_MCP_RECONNECT_BACKOFF_MS")]
    pub reconnect_backoff_ms: u64,

    /// Health probe timeout in milliseconds for active session checks (default: 1500)
    #[arg(long, default_value = "1500", env = "SSH_MCP_HEALTH_PROBE_TIMEOUT_MS")]
    pub health_probe_timeout_ms: u64,

    /// SSH host key checking mode: yes, accept-new, or no
    #[arg(
        long = "strict-host-key-checking",
        env = "SSH_MCP_STRICT_HOST_KEY_CHECKING",
        value_enum,
        default_value_t = HostKeyCheckMode::AcceptNew
    )]
    pub strict_host_key_checking: HostKeyCheckMode,

    /// Path to known_hosts file (default: OpenSSH user known_hosts)
    #[arg(long = "known-hosts", env = "SSH_MCP_KNOWN_HOSTS")]
    pub known_hosts: Option<PathBuf>,
}

/// Parsed and validated configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// SSH host
    pub host: String,

    /// SSH port
    pub port: u16,

    /// SSH username
    pub user: String,

    /// SSH password
    pub password: Option<String>,

    /// Path to SSH private key
    pub key: Option<PathBuf>,

    /// Resolved agent-only authentication settings.
    pub agent: Option<AgentAuth>,
    pub auth_timeout_ms: Option<u64>,

    /// Optional SSH jump host and its independent credentials
    pub jump: Option<JumpConfig>,

    /// Password for su elevation
    pub su_password: Option<String>,

    /// Password for sudo commands
    pub sudo_password: Option<String>,

    /// Command timeout in milliseconds
    pub timeout_ms: u64,

    /// Maximum command length (None = unlimited)
    pub max_chars: Option<usize>,

    /// Maximum output tokens for command execution (None = unlimited)
    pub max_output_tokens: Option<usize>,

    /// Whether sudo_shell and sudo_apply_patch tools are disabled
    pub disable_sudo: bool,

    /// Keepalive interval in seconds
    pub keepalive_interval: u64,

    /// Maximum keepalive failures before disconnecting
    pub keepalive_max: u64,

    /// Number of reconnect retries after the initial attempt
    pub reconnect_retries: u64,

    /// Base reconnect backoff in milliseconds
    pub reconnect_backoff_ms: u64,

    /// Health probe timeout in milliseconds for active session checks
    pub health_probe_timeout_ms: u64,

    /// SSH host key checking mode
    pub strict_host_key_checking: HostKeyCheckMode,

    /// Optional known_hosts file path
    pub known_hosts: Option<PathBuf>,
}

/// One SSH jump host with credentials independent from the target host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    pub key: Option<PathBuf>,
    pub agent: Option<AgentAuth>,
}

impl Config {
    /// Create Config from CLI Args
    pub fn from_args(args: Args) -> Result<Self> {
        let home = std::env::var_os("HOME");
        let auth_sock = std::env::var_os("SSH_AUTH_SOCK");
        Self::from_args_with_env(args, home.as_deref(), auth_sock.as_deref())
    }

    #[cfg(test)]
    fn from_args_with_home(args: Args, home: Option<&OsStr>) -> Result<Self> {
        Self::from_args_with_env(args, home, None)
    }

    pub fn from_args_with_env(
        mut args: Args,
        home: Option<&OsStr>,
        auth_sock: Option<&OsStr>,
    ) -> Result<Self> {
        args.password = sanitize_password(args.password);
        args.jump_password = sanitize_password(args.jump_password);
        args.su_password = sanitize_password(args.su_password);
        args.sudo_password = sanitize_password(args.sudo_password);
        args.key = args
            .key
            .map(|path| expand_key_path(path, home))
            .transpose()?;
        args.jump_key = args
            .jump_key
            .map(|path| expand_key_path(path, home))
            .transpose()?;
        validate_args(&args)?;
        let agent = resolve_agent(
            args.agent,
            args.agent_socket,
            args.agent_identity,
            home,
            auth_sock,
        )?;
        let jump_agent = resolve_agent(
            args.jump_agent,
            args.jump_agent_socket,
            args.jump_agent_identity,
            home,
            auth_sock,
        )?;

        let jump = args
            .jump
            .as_deref()
            .map(parse_jump_endpoint)
            .transpose()?
            .map(|(user, host, port)| JumpConfig {
                host,
                port,
                user,
                password: args.jump_password,
                key: args.jump_key,
                agent: jump_agent,
            });

        let max_chars = parse_max_chars(args.max_chars.as_deref());
        let max_output_tokens = parse_max_output_tokens(args.max_output_tokens.as_deref());

        Ok(Config {
            host: args.host,
            port: args.port,
            user: args.user,
            password: args.password,
            key: args.key,
            agent,
            auth_timeout_ms: args.auth_timeout_ms,
            jump,
            su_password: args.su_password,
            sudo_password: args.sudo_password,
            timeout_ms: args.timeout,
            max_chars,
            max_output_tokens,
            disable_sudo: args.disable_sudo,
            keepalive_interval: args.keepalive_interval,
            keepalive_max: args.keepalive_max,
            reconnect_retries: args.reconnect_retries,
            reconnect_backoff_ms: args.reconnect_backoff_ms,
            health_probe_timeout_ms: args.health_probe_timeout_ms,
            strict_host_key_checking: args.strict_host_key_checking,
            known_hosts: args.known_hosts,
        })
    }
}

fn parse_jump_endpoint(value: &str) -> Result<(String, String, u16)> {
    let (user, endpoint) = value.split_once('@').ok_or_else(|| {
        SshMcpError::Config("--jump must use USER@HOST[:PORT] format".to_string())
    })?;
    if user.is_empty() || endpoint.is_empty() || endpoint.contains('@') {
        return Err(SshMcpError::Config(
            "--jump must use USER@HOST[:PORT] format".to_string(),
        ));
    }

    let (host, port) = match endpoint.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().map_err(|_| {
                SshMcpError::Config("--jump port must be an integer from 1 to 65535".to_string())
            })?;
            (host, port)
        }
        None => (endpoint, 22),
    };

    if host.is_empty()
        || port == 0
        || user.chars().any(char::is_whitespace)
        || host.chars().any(char::is_whitespace)
    {
        return Err(SshMcpError::Config(
            "--jump must use USER@HOST[:PORT] with non-empty values".to_string(),
        ));
    }

    Ok((user.to_string(), host.to_string(), port))
}

fn expand_key_path(path: PathBuf, home: Option<&OsStr>) -> Result<PathBuf> {
    if !path.as_os_str().as_encoded_bytes().starts_with(b"~/") {
        return Ok(path);
    }

    let home = home.filter(|value| !value.is_empty()).ok_or_else(|| {
        SshMcpError::Config(format!(
            "Cannot expand SSH key path {}: HOME is not set",
            path.display()
        ))
    })?;
    let suffix = path
        .strip_prefix("~")
        .expect("leading ~/ path must have a tilde component");

    Ok(Path::new(home).join(suffix))
}

fn resolve_agent(
    enabled: bool,
    socket: Option<PathBuf>,
    identity: Option<PathBuf>,
    home: Option<&OsStr>,
    auth_sock: Option<&OsStr>,
) -> Result<Option<AgentAuth>> {
    if !enabled {
        return Ok(None);
    }
    let socket = socket.or_else(|| auth_sock.filter(|s| !s.is_empty()).map(PathBuf::from))
        .filter(|s| !s.as_os_str().is_empty())
        .ok_or_else(|| SshMcpError::Config("SSH-agent authentication requires --agent-socket (or --jump-agent-socket) or SSH_AUTH_SOCK".into()))?;
    let socket = expand_key_path(socket, home)?;
    let identity = identity
        .map(|path| expand_key_path(path, home).and_then(|path| load_public_key_selector(&path)))
        .transpose()?;
    Ok(Some(AgentAuth { socket, identity }))
}

/// Load exactly one ordinary OpenSSH public key without reading unbounded input.
pub fn load_public_key_selector(path: &Path) -> Result<russh::keys::PublicKey> {
    let file = std::fs::File::open(path).map_err(|error| {
        SshMcpError::Config(format!(
            "Cannot open public key selector {}: {error}",
            path.display()
        ))
    })?;
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            SshMcpError::Config(format!(
                "Cannot read public key selector {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() > 16 * 1024 {
        return Err(SshMcpError::Config(
            "Public key selector exceeds 16 KiB".into(),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        SshMcpError::Config("Public key selector must be UTF-8 OpenSSH public key text".into())
    })?;
    if text.contains("PRIVATE KEY") {
        return Err(SshMcpError::Config(
            "This option takes a public key (.pub), not a private key".into(),
        ));
    }
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    let line = lines.next().ok_or_else(|| {
        SshMcpError::Config("Public key selector must contain exactly one public key".into())
    })?;
    if lines.next().is_some() {
        return Err(SshMcpError::Config(
            "Public key selector must contain exactly one public key".into(),
        ));
    }
    if line
        .split_whitespace()
        .next()
        .is_some_and(|algorithm| algorithm.ends_with("-cert-v01@openssh.com"))
    {
        return Err(SshMcpError::Config(
            "Certificate selectors are not supported in this release".into(),
        ));
    }
    russh::keys::PublicKey::from_openssh(line)
        .map_err(|_| SshMcpError::Config("Invalid OpenSSH public key selector".into()))
}

/// Validate CLI arguments
fn validate_args(args: &Args) -> Result<()> {
    let mut errors = Vec::new();

    if args.host.is_empty() {
        errors.push("Missing required --host".to_string());
    }

    if args.user.is_empty() {
        errors.push("Missing required --user".to_string());
    }

    if !args.agent && args.password.is_none() && args.key.is_none() {
        errors.push("Must provide --password, --key, or --agent".into());
    }
    if args.agent && args.password.is_some() {
        errors.push("--agent conflicts with --password / SSH_MCP_PASSWORD".into());
    }
    if args.agent && args.key.is_some() {
        errors.push("--agent conflicts with --key / SSH_MCP_KEY".into());
    }
    if !args.agent && (args.agent_socket.is_some() || args.agent_identity.is_some()) {
        errors.push("--agent-socket and --agent-identity require --agent".into());
    }
    let jump_credentials = usize::from(args.jump_key.is_some())
        + usize::from(args.jump_password.is_some())
        + usize::from(args.jump_agent);
    if args.jump.is_none()
        && (jump_credentials > 0
            || args.jump_agent_socket.is_some()
            || args.jump_agent_identity.is_some())
    {
        errors.push("Jump credentials require --jump".into());
    } else if args.jump.is_some() && jump_credentials != 1 {
        errors.push("--jump requires exactly one of --jump-key / SSH_MCP_JUMP_KEY, --jump-password / SSH_MCP_JUMP_PASSWORD, or --jump-agent".into());
    }
    if !args.jump_agent && (args.jump_agent_socket.is_some() || args.jump_agent_identity.is_some())
    {
        errors.push("--jump-agent-socket and --jump-agent-identity require --jump-agent".into());
    }
    if args
        .auth_timeout_ms
        .is_some_and(|value| !(1..=600_000).contains(&value))
    {
        errors.push("--auth-timeout-ms must be between 1 and 600000".into());
    }
    #[cfg(not(unix))]
    if args.agent || args.jump_agent {
        errors.push("SSH-agent authentication requires a Unix-domain socket (not available on this platform)".into());
    }

    // If key is provided, check if file exists
    if !args.agent
        && let Some(key_path) = &args.key
        && !key_path.exists()
    {
        errors.push(format!("SSH key file not found: {}", key_path.display()));
    }

    if !args.jump_agent
        && let Some(key_path) = &args.jump_key
        && !key_path.exists()
    {
        errors.push(format!(
            "Jump SSH key file not found: {}",
            key_path.display()
        ));
    }

    if args.reconnect_retries > MAX_RECONNECT_RETRIES {
        errors.push(format!(
            "--reconnect-retries must be <= {MAX_RECONNECT_RETRIES}"
        ));
    }

    if !(MIN_RECONNECT_BACKOFF_MS..=MAX_RECONNECT_BACKOFF_MS).contains(&args.reconnect_backoff_ms) {
        errors.push(format!(
            "--reconnect-backoff-ms must be between {MIN_RECONNECT_BACKOFF_MS} and {MAX_RECONNECT_BACKOFF_MS}"
        ));
    }

    if !(MIN_HEALTH_PROBE_TIMEOUT_MS..=MAX_HEALTH_PROBE_TIMEOUT_MS)
        .contains(&args.health_probe_timeout_ms)
    {
        errors.push(format!(
            "--health-probe-timeout-ms must be between {MIN_HEALTH_PROBE_TIMEOUT_MS} and {MAX_HEALTH_PROBE_TIMEOUT_MS}"
        ));
    }

    if !errors.is_empty() {
        return Err(SshMcpError::Config(format!(
            "Configuration error:\n{}",
            errors.join("\n")
        )));
    }

    Ok(())
}

/// Default max output tokens (16_000 ≈ 64KB)
pub const DEFAULT_MAX_OUTPUT_TOKENS: Option<usize> = Some(16_000);

/// Parse max_chars argument
///
/// - "none" (case-insensitive) → None (unlimited)
/// - "0" or negative → None (unlimited)
/// - positive integer → Some(value)
/// - None (not provided) → DEFAULT_MAX_CHARS
pub fn parse_max_chars(value: Option<&str>) -> Option<usize> {
    match value {
        None => DEFAULT_MAX_CHARS,
        Some(s) => {
            let lowered = s.to_lowercase();
            if lowered == "none" {
                return None;
            }

            match s.parse::<i64>() {
                Ok(n) if n <= 0 => None,
                Ok(n) => Some(n as usize),
                Err(_) => DEFAULT_MAX_CHARS,
            }
        }
    }
}

/// Parse max_output_tokens argument
///
/// - "none" (case-insensitive) → None (unlimited)
/// - "0" or negative → None (unlimited)
/// - positive integer with optional "k" suffix (e.g., "12k") → Some(value)
/// - None (not provided) → DEFAULT_MAX_OUTPUT_TOKENS
pub fn parse_max_output_tokens(value: Option<&str>) -> Option<usize> {
    match value {
        None => DEFAULT_MAX_OUTPUT_TOKENS,
        Some(s) => {
            let lowered = s.to_lowercase().replace(" ", "");
            if lowered == "none" {
                return None;
            }

            // Try to parse with k suffix
            if lowered.ends_with('k') {
                let num_part = &lowered[..lowered.len() - 1];
                match num_part.parse::<i64>() {
                    Ok(n) if n <= 0 => None,
                    Ok(n) => Some((n as usize).saturating_mul(1_000)),
                    Err(_) => DEFAULT_MAX_OUTPUT_TOKENS,
                }
            } else {
                match lowered.parse::<i64>() {
                    Ok(n) if n <= 0 => None,
                    Ok(n) => Some(n as usize),
                    Err(_) => DEFAULT_MAX_OUTPUT_TOKENS,
                }
            }
        }
    }
}

/// Sanitize password: return None if empty
fn sanitize_password(password: Option<String>) -> Option<String> {
    password.filter(|p| !p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Args {
        Args {
            host: "localhost".to_string(),
            port: 22,
            user: "test".to_string(),
            password: Some("secret".to_string()),
            key: None,
            agent: false,
            agent_socket: None,
            agent_identity: None,
            auth_timeout_ms: None,
            jump_agent: false,
            jump_agent_socket: None,
            jump_agent_identity: None,
            jump: None,
            jump_key: None,
            jump_password: None,
            spool_dir: None,
            su_password: None,
            sudo_password: None,
            timeout: DEFAULT_TIMEOUT_MS,
            max_chars: None,
            disable_sudo: false,
            max_output_tokens: None,
            log_level: "info".to_string(),
            log_file: None,
            log_format: "text".to_string(),
            log_rotation: "daily".to_string(),
            keepalive_interval: 30,
            keepalive_max: 3,
            reconnect_retries: DEFAULT_RECONNECT_RETRIES,
            reconnect_backoff_ms: DEFAULT_RECONNECT_BACKOFF_MS,
            health_probe_timeout_ms: DEFAULT_HEALTH_PROBE_TIMEOUT_MS,
            strict_host_key_checking: HostKeyCheckMode::AcceptNew,
            known_hosts: None,
        }
    }

    #[test]
    fn test_parse_max_chars_none_string() {
        assert_eq!(parse_max_chars(Some("none")), None);
        assert_eq!(parse_max_chars(Some("None")), None);
        assert_eq!(parse_max_chars(Some("NONE")), None);
    }

    #[test]
    fn test_parse_max_chars_zero_or_negative() {
        assert_eq!(parse_max_chars(Some("0")), None);
        assert_eq!(parse_max_chars(Some("-1")), None);
        assert_eq!(parse_max_chars(Some("-100")), None);
    }

    #[test]
    fn test_parse_max_chars_positive() {
        assert_eq!(parse_max_chars(Some("500")), Some(500));
        assert_eq!(parse_max_chars(Some("2000")), Some(2000));
    }

    #[test]
    fn test_parse_max_chars_invalid() {
        // Invalid strings should return default
        assert_eq!(parse_max_chars(Some("abc")), DEFAULT_MAX_CHARS);
        assert_eq!(parse_max_chars(Some("")), DEFAULT_MAX_CHARS);
    }

    #[test]
    fn test_parse_max_chars_not_provided() {
        assert_eq!(parse_max_chars(None), DEFAULT_MAX_CHARS);
    }

    #[test]
    fn test_config_from_args_uses_default_max_chars() {
        let config = Config::from_args(base_args()).unwrap();

        assert_eq!(config.max_chars, Some(64_000));
        assert_eq!(config.strict_host_key_checking, HostKeyCheckMode::AcceptNew);
        assert!(config.known_hosts.is_none());
    }

    #[test]
    fn test_config_expands_tilde_key_before_validation() {
        let home = tempfile::tempdir().unwrap();
        let key_path = home.path().join(".ssh/id_ed25519");
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(&key_path, "test key").unwrap();

        let mut args = base_args();
        args.password = None;
        args.key = Some(PathBuf::from("~/.ssh/id_ed25519"));

        let config = Config::from_args_with_home(args, Some(home.path().as_os_str())).unwrap();
        assert_eq!(config.key, Some(key_path));
    }

    #[test]
    fn test_config_parses_jump_with_independent_key() {
        let home = tempfile::tempdir().unwrap();
        let key_path = home.path().join(".ssh/jump_key");
        std::fs::create_dir_all(key_path.parent().unwrap()).unwrap();
        std::fs::write(&key_path, "test key").unwrap();

        let mut args = base_args();
        args.jump = Some("jump-user@example.com:2200".to_string());
        args.jump_key = Some(PathBuf::from("~/.ssh/jump_key"));

        let config = Config::from_args_with_home(args, Some(home.path().as_os_str())).unwrap();
        assert_eq!(
            config.jump,
            Some(JumpConfig {
                host: "example.com".to_string(),
                port: 2200,
                user: "jump-user".to_string(),
                password: None,
                key: Some(key_path),
                agent: None,
            })
        );
    }

    #[test]
    fn test_jump_validation_requires_one_credential() {
        let mut missing = base_args();
        missing.jump = Some("jump-user@example.com".to_string());
        assert!(Config::from_args(missing).is_err());

        let mut orphan = base_args();
        orphan.jump_password = Some("secret".to_string());
        assert!(Config::from_args(orphan).is_err());

        let key = tempfile::NamedTempFile::new().unwrap();
        let mut both = base_args();
        both.jump = Some("jump-user@example.com".to_string());
        both.jump_key = Some(key.path().to_path_buf());
        both.jump_password = Some("secret".to_string());
        assert!(Config::from_args(both).is_err());
    }

    #[test]
    fn test_empty_password_is_absent_before_validation() {
        let mut args = base_args();
        args.password = Some(String::new());
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_expand_key_path_only_expands_leading_home_prefix() {
        let home = OsStr::new("/home/test");
        let cases = [
            ("~", "~"),
            ("~user/key", "~user/key"),
            ("dir/~/key", "dir/~/key"),
            ("$HOME/key", "$HOME/key"),
            (r"~\key", r"~\key"),
            ("/tmp/key", "/tmp/key"),
        ];

        for (input, expected) in cases {
            assert_eq!(
                expand_key_path(PathBuf::from(input), Some(home)).unwrap(),
                PathBuf::from(expected)
            );
        }
        assert_eq!(
            expand_key_path(PathBuf::from("~/.ssh/id_ed25519"), Some(home)).unwrap(),
            PathBuf::from("/home/test/.ssh/id_ed25519")
        );
    }

    #[test]
    fn test_expand_key_path_requires_home() {
        for home in [None, Some(OsStr::new(""))] {
            let error = expand_key_path(PathBuf::from("~/.ssh/id_ed25519"), home).unwrap_err();
            assert!(error.to_string().contains("HOME is not set"));
        }
    }

    #[test]
    fn test_args_parse_host_key_options() {
        let args = Args::try_parse_from([
            "ssh-mcp",
            "--host",
            "example.com",
            "--user",
            "alice",
            "--password",
            "secret",
            "--strict-host-key-checking",
            "yes",
            "--known-hosts",
            "/tmp/known_hosts",
        ])
        .unwrap();

        assert_eq!(args.strict_host_key_checking, HostKeyCheckMode::Yes);
        assert_eq!(args.known_hosts, Some(PathBuf::from("/tmp/known_hosts")));
    }

    #[test]
    fn test_args_parse_spool_dir() {
        let args = Args::try_parse_from([
            "ssh-mcp",
            "--host",
            "example.com",
            "--user",
            "alice",
            "--password",
            "secret",
            "--spool-dir",
            "/tmp/ssh-mcp-alice",
        ])
        .unwrap();

        assert_eq!(args.spool_dir, Some(PathBuf::from("/tmp/ssh-mcp-alice")));
    }

    #[test]
    fn test_sanitize_password() {
        assert_eq!(
            sanitize_password(Some("secret".to_string())),
            Some("secret".to_string())
        );
        assert_eq!(sanitize_password(Some(String::new())), None);
        assert_eq!(sanitize_password(None), None);
    }

    #[test]
    fn test_parse_max_output_tokens_none_string() {
        assert_eq!(parse_max_output_tokens(Some("none")), None);
        assert_eq!(parse_max_output_tokens(Some("None")), None);
        assert_eq!(parse_max_output_tokens(Some("NONE")), None);
    }

    #[test]
    fn test_parse_max_output_tokens_zero_or_negative() {
        assert_eq!(parse_max_output_tokens(Some("0")), None);
        assert_eq!(parse_max_output_tokens(Some("-1")), None);
        assert_eq!(parse_max_output_tokens(Some("-100")), None);
    }

    #[test]
    fn test_parse_max_output_tokens_positive() {
        assert_eq!(parse_max_output_tokens(Some("500")), Some(500));
        assert_eq!(parse_max_output_tokens(Some("12000")), Some(12_000));
    }

    #[test]
    fn test_parse_max_output_tokens_with_k_suffix() {
        assert_eq!(parse_max_output_tokens(Some("12k")), Some(12_000));
        assert_eq!(parse_max_output_tokens(Some("5K")), Some(5_000));
        assert_eq!(parse_max_output_tokens(Some("100k")), Some(100_000));
    }

    #[test]
    fn test_parse_max_output_tokens_invalid() {
        // Invalid strings should return default
        assert_eq!(
            parse_max_output_tokens(Some("abc")),
            DEFAULT_MAX_OUTPUT_TOKENS
        );
        assert_eq!(parse_max_output_tokens(Some("")), DEFAULT_MAX_OUTPUT_TOKENS);
    }

    #[test]
    fn test_parse_max_output_tokens_not_provided() {
        assert_eq!(parse_max_output_tokens(None), DEFAULT_MAX_OUTPUT_TOKENS);
    }

    #[test]
    fn test_validate_args_rejects_reconnect_retries_out_of_range() {
        let mut args = base_args();
        args.reconnect_retries = MAX_RECONNECT_RETRIES.saturating_add(1);

        let result = validate_args(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_args_rejects_reconnect_backoff_out_of_range() {
        let mut args = base_args();
        args.reconnect_backoff_ms = MIN_RECONNECT_BACKOFF_MS.saturating_sub(1);

        let result = validate_args(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_args_rejects_health_probe_timeout_out_of_range() {
        let mut args = base_args();
        args.health_probe_timeout_ms = MAX_HEALTH_PROBE_TIMEOUT_MS.saturating_add(1);

        let result = validate_args(&args);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(unix))]
    fn agent_authentication_is_rejected_on_non_unix_platforms() {
        let mut args = base_args();
        args.password = None;
        args.agent = true;
        args.agent_socket = Some("agent.sock".into());
        let error = Config::from_args_with_env(args, None, None).unwrap_err();
        assert!(error.to_string().contains("Unix-domain socket"));
    }

    #[test]
    #[cfg(unix)]
    fn authentication_matrices_and_timeout_boundaries() {
        let key = tempfile::NamedTempFile::new().unwrap();
        for agent in [false, true] {
            for password in [false, true] {
                for private_key in [false, true] {
                    let mut args = base_args();
                    args.agent = agent;
                    args.password = password.then(|| "secret".into());
                    args.key = private_key.then(|| key.path().to_path_buf());
                    let valid = if agent {
                        !password && !private_key
                    } else {
                        password || private_key
                    };
                    assert_eq!(
                        validate_args(&args).is_ok(),
                        valid,
                        "target: {agent}/{password}/{private_key}"
                    );
                    for jump in [false, true] {
                        args = base_args();
                        args.jump = jump.then(|| "user@jump".into());
                        args.jump_agent = agent;
                        args.jump_password = password.then(|| "secret".into());
                        args.jump_key = private_key.then(|| key.path().to_path_buf());
                        let count =
                            usize::from(agent) + usize::from(password) + usize::from(private_key);
                        assert_eq!(
                            validate_args(&args).is_ok(),
                            if jump { count == 1 } else { count == 0 },
                            "jump: {jump}/{agent}/{password}/{private_key}"
                        );
                    }
                }
            }
        }
        for (budget, valid) in [(0, false), (1, true), (600_000, true), (600_001, false)] {
            let mut args = base_args();
            args.auth_timeout_ms = Some(budget);
            assert_eq!(validate_args(&args).is_ok(), valid);
        }
        for jump in [false, true] {
            let mut args = base_args();
            if jump {
                args.jump_agent_identity = Some("selector.pub".into());
            } else {
                args.agent_socket = Some("socket".into());
            }
            assert!(validate_args(&args).is_err());
        }
    }

    #[test]
    #[cfg(unix)]
    fn sockets_are_snapshotted_and_endpoints_independent() {
        let mut args = base_args();
        args.password = None;
        args.agent = true;
        args.agent_socket = Some("~/target.sock".into());
        args.jump = Some("jump@host".into());
        args.jump_agent = true;
        let config = Config::from_args_with_env(
            args,
            Some(OsStr::new("/home/test")),
            Some(OsStr::new("/env/socket")),
        )
        .unwrap();
        assert_eq!(
            config.agent.unwrap().socket,
            PathBuf::from("/home/test/target.sock")
        );
        assert_eq!(
            config.jump.unwrap().agent.unwrap().socket,
            PathBuf::from("/env/socket")
        );
        let mut args = base_args();
        args.password = None;
        args.agent = true;
        assert!(
            Config::from_args_with_env(args, None, None)
                .unwrap_err()
                .to_string()
                .contains("SSH_AUTH_SOCK")
        );
    }

    #[test]
    fn selectors_reject_unsafe_and_ambiguous_input() {
        let file = tempfile::NamedTempFile::new().unwrap();
        for (text, expected) in [
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----".to_string(),
                "public key (.pub)",
            ),
            (
                "ssh-ed25519 garbage\nssh-ed25519 garbage".to_string(),
                "exactly one",
            ),
            (
                "ssh-ed25519-cert-v01@openssh.com garbage".to_string(),
                "Certificate selectors",
            ),
            ("garbage".to_string(), "Invalid OpenSSH"),
            ("# comment\n\n".to_string(), "exactly one"),
            ("x".repeat(16 * 1024 + 1), "exceeds 16 KiB"),
        ] {
            std::fs::write(file.path(), text).unwrap();
            assert!(
                load_public_key_selector(file.path())
                    .unwrap_err()
                    .to_string()
                    .contains(expected)
            );
        }
    }

    #[test]
    fn selectors_accept_public_key_algorithms_and_comments() {
        for algorithm in [
            russh::keys::Algorithm::Ed25519,
            russh::keys::Algorithm::Ecdsa {
                curve: russh::keys::ssh_key::EcdsaCurve::NistP256,
            },
            russh::keys::Algorithm::Rsa { hash: None },
        ] {
            let key = russh::keys::PrivateKey::random(
                &mut getrandom::rand_core::UnwrapErr(getrandom::SysRng),
                algorithm,
            )
            .unwrap();
            let file = tempfile::NamedTempFile::new().unwrap();
            let public = key.public_key().to_openssh().unwrap();
            std::fs::write(file.path(), format!("# selection\n\n{public}\n")).unwrap();
            assert_eq!(
                load_public_key_selector(file.path()).unwrap().key_data(),
                key.public_key().key_data()
            );
        }
    }

    #[test]
    fn false_agent_environment_is_disabled() {
        const CHILD: &str = "SESSHION_CONFIG_ENV_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let args = Args::try_parse_from([
                "ssh-mcp",
                "--host",
                "host",
                "--user",
                "user",
                "--password",
                "secret",
            ])
            .unwrap();
            assert!(!args.agent);
            assert!(!args.jump_agent);
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "config::tests::false_agent_environment_is_disabled",
                "--nocapture",
            ])
            .env_clear()
            .env(CHILD, "1")
            .env("SSH_MCP_AGENT", "false")
            .env("SSH_MCP_JUMP_AGENT", "false")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
