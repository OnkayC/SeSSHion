# russh - Async SSH Library (v0.56.0)

> Source: https://docs.rs/russh/latest/russh/

## Overview

Server and client SSH asynchronous library, based on tokio/futures.

The library uses **handlers**: types that implement `client::Handler` for clients and `server::Handler` for servers.

## Writing SSH Clients

Use the `russh::client` module:

1. Implement `client::Handler` trait
2. Use `client::connect()` to establish connection
3. Open channels with `channel_open_session()`
4. Execute commands with `Channel::exec()`

### Basic SSH Client Flow

```rust
use russh::*;
use russh::client::*;
use russh_keys::*;

struct MyHandler;

impl client::Handler for MyHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &ssh_key::PublicKey
    ) -> Result<bool, Self::Error> {
        Ok(true) // Accept all keys (don't do this in production!)
    }
}

async fn connect_and_exec() -> Result<()> {
    let config = client::Config::default();
    let mut session = client::connect(
        Arc::new(config),
        ("hostname", 22),
        MyHandler
    ).await?;

    // Authenticate
    let auth_res = session.authenticate_password("user", "password").await?;

    // Open channel and execute command
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, "ls -la").await?;

    // Read output
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => println!("{}", String::from_utf8_lossy(&data)),
            ChannelMsg::ExitStatus { exit_status } => println!("Exit: {}", exit_status),
            _ => {}
        }
    }

    Ok(())
}
```

## Proxy commands in SeSSHion

Use `--proxy-command` (or `SSH_MCP_PROXY_COMMAND`) to connect through a local
program that carries SSH bytes on stdin and stdout. For Cloudflare Access:

```sh
ssh-mcp --host ssh-grok1.onkay.dev --user box --agent \
  --proxy-command 'exec /opt/homebrew/bin/cloudflared access ssh --hostname %h'
```

The configured command runs under `/bin/sh -c` when SSH is first needed,
including the CLI's startup environment probe. That probe shares a 3-second
total deadline across proxy startup, SSH authentication, and metadata collection.
A successful route is reused by tools; otherwise MCP starts with unknown
metadata and later tools can connect using their normal authentication budgets.
SeSSHion expands `%h` to the destination hostname, `%p` to its SSH port, and
`%r` to its username as shell-quoted words. Keep these placeholders outside
existing shell quotes. Use `%%` for a literal percent, including percent signs
in commands such as `printf`. Unsupported or incomplete tokens are rejected.

The proxy only supplies the transport: normal host-key verification and
password, key, or agent authentication still apply. The proxy process group
is terminated on connection close, failed authentication, handshake timeout,
or cancellation. Proxy stderr remains on the MCP server's stderr.

Native command execution and exec-raw transfers share the proxied connection.
Explicit SFTP, SCP, and rsync transfers receive the same proxy command through
OpenSSH; templates are wrapped in a POSIX shell and literal percent signs are
protected against a second OpenSSH expansion. Agent mode continues to use
exec-raw for automatic transfers.

Proxy commands require a POSIX shell and cannot be combined with `--jump`.
SeSSHion does not automatically read `ProxyCommand` from `~/.ssh/config`; set
the option explicitly in each MCP destination's launch arguments.

## Key Types

### Structs

| Type | Description |
|------|-------------|
| `Channel` | SSH channel for command execution |
| `ChannelId` | Unique channel identifier |
| `ChannelReadHalf` | Read half of split channel |
| `ChannelWriteHalf` | Write half of split channel |
| `ChannelStream` | AsyncRead/AsyncWrite stream |
| `Limits` | Connection limits |
| `Preferred` | Preferred algorithms |

### Enums

| Type | Description |
|------|-------------|
| `ChannelMsg` | Messages received from channel (Data, Eof, ExitStatus, etc.) |
| `Error` | SSH errors |
| `Disconnect` | Disconnect reasons |
| `Sig` | Signal types |
| `Pty` | PTY modes |

## Channel Messages (`ChannelMsg`)

Used with `Channel::wait()`:

```rust
enum ChannelMsg {
    Data { data: CryptoVec },
    ExtendedData { data: CryptoVec, ext: u32 },
    Eof,
    Close,
    ExitStatus { exit_status: u32 },
    ExitSignal { signal_name: Sig, ... },
    // ... more variants
}
```

## PTY Shell (for interactive commands like `su`)

```rust
// Request PTY for interactive shell
channel.request_pty(
    true,           // want_reply
    "xterm",        // terminal type
    80,             // columns
    24,             // rows
    0, 0,           // pixel dimensions
    &[]             // terminal modes
).await?;

// Request shell
channel.request_shell(true).await?;

// Now you can write commands and read responses interactively
channel.data(b"su -\n").await?;
```

## Modules

- `client` - SSH client implementation
- `server` - SSH server implementation  
- `cipher` - Encryption ciphers
- `kex` - Key exchange
- `keys` - Key handling
- `mac` - Message authentication
- `compression` - Compression support

## Design Principles

- Uses buffered I/O for encryption
- Event loop with handler callbacks
- Internally manages encryption/decryption buffers
