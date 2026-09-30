//! Local proxy commands providing an SSH byte stream.

use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::error::{Result, SshMcpError};

/// Expand unquoted proxy placeholders into shell-quoted words.
/// The command itself is trusted local configuration, not remote input.
pub(crate) fn expand_proxy_command(
    command: &str,
    host: &str,
    port: u16,
    user: &str,
) -> Result<String> {
    if command.trim().is_empty() || command.contains('\0') {
        return Err(SshMcpError::config(
            "proxy command must be nonempty and contain no NUL bytes",
        ));
    }
    let mut expanded = String::with_capacity(command.len());
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            expanded.push(ch);
            continue;
        }
        match chars.next() {
            Some('%') => expanded.push('%'),
            Some(token @ ('h' | 'p' | 'r')) => {
                expanded.push('\'');
                match token {
                    'h' | 'r' => {
                        for ch in if token == 'h' { host } else { user }.chars() {
                            if ch == '\'' {
                                expanded.push_str("'\"'\"'");
                            } else {
                                expanded.push(ch);
                            }
                        }
                    }
                    'p' => write!(&mut expanded, "{port}").expect("writing to String"),
                    _ => unreachable!(),
                }
                expanded.push('\'');
            }
            Some(token) => {
                return Err(SshMcpError::config(format!(
                    "unsupported proxy command token %{token}; use %h, %p, %r, or %%"
                )));
            }
            None => {
                return Err(SshMcpError::config(
                    "incomplete proxy command token; use %% for a literal percent",
                ));
            }
        }
    }
    Ok(expanded)
}

/// Owns the proxy and terminates its entire process group on every exit path.
pub(super) struct ProxyProcess {
    child: Child,
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self
            .child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = self.child.start_kill();
    }
}

pub(super) struct ProxyStream {
    input: Option<ChildStdin>,
    output: ChildStdout,
}

impl ProxyStream {
    pub(super) fn spawn(command: &str) -> Result<(Self, ProxyProcess)> {
        if !cfg!(unix) {
            return Err(SshMcpError::config("proxy commands require a POSIX shell"));
        }
        let mut process = Command::new("/bin/sh");
        process
            .args(["-c", command])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        #[cfg(unix)]
        process.process_group(0);
        let child = process.spawn().map_err(|error| {
            SshMcpError::connection(format!("failed to spawn proxy command: {error}"))
        })?;
        let mut guard = ProxyProcess { child };
        let input = guard
            .child
            .stdin
            .take()
            .ok_or_else(|| SshMcpError::connection("proxy command stdin pipe missing"))?;
        let output = guard
            .child
            .stdout
            .take()
            .ok_or_else(|| SshMcpError::connection("proxy command stdout pipe missing"))?;
        Ok((
            Self {
                input: Some(input),
                output,
            },
            guard,
        ))
    }
}

impl AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.output).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.input.as_mut() {
            Some(input) => Pin::new(input).poll_write(cx, buf),
            None => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "proxy input closed",
            ))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.input.as_mut() {
            Some(input) => Pin::new(input).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(input) = self.input.as_mut() {
            match Pin::new(input).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => {
                    self.input.take();
                }
                result => return result,
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn substitutions_are_literal_shell_arguments() {
        let command = expand_proxy_command(
            "printf '%s\\n' %h %p %r %%",
            "host'; exit 7; #",
            8022,
            "user with spaces",
        );
        // printf's own percent must be escaped in the proxy template.
        assert!(command.is_err());
        let command = expand_proxy_command(
            "printf '%%s\\n' %h %p %r %%",
            "host'; exit 7; #",
            8022,
            "user with spaces",
        )
        .unwrap();
        let (mut stream, mut process) = ProxyStream::spawn(&command).unwrap();
        let mut output = String::new();
        stream.read_to_string(&mut output).await.unwrap();
        assert_eq!(output, "host'; exit 7; #\n8022\nuser with spaces\n%\n");
        assert!(process.child.wait().await.unwrap().success());
    }

    #[tokio::test]
    async fn proxy_stream_transports_bytes_in_both_directions() {
        let (mut stream, _process) = ProxyStream::spawn("exec cat").unwrap();
        stream.write_all(b"SSH-2.0-proxy-smoke\r\n").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, b"SSH-2.0-proxy-smoke\r\n");
    }

    #[tokio::test]
    async fn dropping_proxy_kills_descendants_even_with_open_stream() {
        let (mut stream, process) =
            ProxyStream::spawn("sleep 60 & printf 'ready\\n'; wait").unwrap();
        let mut ready = [0; 6];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ready, b"ready\n");
        drop(process);
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        assert!(remaining.is_empty());
    }
}
