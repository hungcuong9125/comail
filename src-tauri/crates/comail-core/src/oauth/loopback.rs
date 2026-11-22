//! Loopback listener for OAuth's authorization-code flow (RFC 8252 §7.3):
//! after consent the browser is redirected to `http://localhost:port/?code=
//! ...&state=...`; we answer the browser with a "done" page and hand the code
//! back to `exchange_code`. Per RFC 8252 §8.1 both 127.0.0.1 and ::1 may
//! resolve for `localhost`, and only the IPv4 form is guaranteed on every OS —
//! so we bind both (IPv6 best-effort) and tell the provider `localhost`.
//! Only loopback addresses are bound: the redirect endpoint must never be
//! reachable off the machine.

use crate::error::{CoreError, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct LoopbackServer {
    v4: TcpListener,
    v6: Option<TcpListener>,
    pub port: u16,
}

/// Per-connection budget: a browser preconnect or a garbage connection gets a
/// few seconds to deliver a request, then is dropped so it can never stall
/// the real redirect the way the old single-read accept loop could.
const CONN_DEADLINE: Duration = Duration::from_secs(5);
/// The request head (request line + headers) is small; cap the read so a
/// flooding client can't grow memory.
const MAX_REQUEST_HEAD: usize = 16 * 1024;

impl LoopbackServer {
    /// Bind an ephemeral port on the IPv4 loopback and, when the OS supports
    /// it, the same port on the IPv6 loopback. Failure to bind `::1` is not
    /// fatal: some environments lack IPv6, and the v4 listener still serves
    /// the redirect.
    pub async fn bind() -> Result<Self> {
        let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = v4.local_addr()?.port();
        let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await.ok();
        tracing::debug!(
            port,
            ipv6 = v6.is_some(),
            "oauth: loopback redirect server listening"
        );
        Ok(Self { v4, v6, port })
    }

    pub fn redirect_uri(&self) -> String {
        // `localhost` (not the 127.0.0.1 literal) matches the redirect URI
        // registered for desktop OAuth clients and is what Microsoft requires
        // to ignore the ephemeral port. We listen on both loopback stacks so
        // whichever address `localhost` resolves to reaches us.
        format!("http://localhost:{}/", self.port)
    }

    /// Wait for the OAuth redirect carrying `?code=...&state=...` (or
    /// `?error=...`). Each accepted connection runs on its own task under a
    /// short read deadline: browsers routinely open speculative connections
    /// that send nothing, and awaiting one inline would block the real
    /// redirect until the outer timeout.
    pub async fn wait_for_code(self, timeout: Duration) -> Result<AuthCode> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Option<AuthCode>>>(32);
        let fut = async {
            loop {
                tokio::select! {
                    accept = async {
                        match &self.v6 {
                            Some(v6) => tokio::select! {
                                r = self.v4.accept() => r,
                                r = v6.accept() => r,
                            },
                            None => self.v4.accept().await,
                        }
                    } => {
                        let (stream, _) = accept?;
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(handle_connection(stream).await).await;
                        });
                    }
                    msg = rx.recv() => match msg {
                        // The real redirect: done.
                        Some(Ok(Some(code))) => return Ok(code),
                        // OAuth error or unreadable request: abort sign-in.
                        Some(Err(e)) => return Err(e),
                        // A speculative/garbage connection was dropped; or the
                        // channel drained (impossible — we hold `tx`).
                        _ => {}
                    },
                }
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| CoreError::Auth("sign-in timed out".into()))?
    }
}

/// The decoded authorization response: `code` for the token exchange, `state`
/// so the caller can match it against the original request.
pub struct AuthCode {
    pub code: String,
    pub state: Option<String>,
}

/// Extract `code`/`state`/`error` from the callback's query string.
/// `url::form_urlencoded` is panic-free on malformed percent escapes and
/// multi-byte UTF-8 — the hand-rolled decoder it replaces indexed bytes but
/// sliced `&str`, which panicked on inputs like `%aé`.
fn parse_callback_query(query: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            _ => {}
        }
    }
    (code, state, error)
}

/// Read one request head: up to `\r\n\r\n`, EOF, the size cap, or the
/// per-connection deadline — so a request split across TCP segments is
/// reassembled instead of truncated like the old single `read`. `None` means
/// the peer sent nothing at all or reset (a dropped speculative connection)
/// and must be ignored rather than abort the sign-in.
async fn read_request_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + CONN_DEADLINE;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_REQUEST_HEAD {
            return Some(buf);
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return (!buf.is_empty()).then_some(buf),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            // Browsers open speculative connections to localhost and drop
            // them; a reset or empty read must not abort the whole sign-in.
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "oauth: ignoring dropped loopback connection");
                return None;
            }
            // Stalled mid-request: parse whatever arrived (the request line
            // may still be complete).
            Err(_) => return (!buf.is_empty()).then_some(buf),
        }
    }
}

/// Handle one accepted connection. Returns `Ok(Some(code))` on a callback
/// carrying a code, `Err` if the provider redirected back with an error, and
/// `Ok(None)` for connections we should ignore (dropped/speculative/stray
/// requests — browsers also fire `GET /favicon.ico` at localhost pages).
async fn handle_connection(mut stream: TcpStream) -> Result<Option<AuthCode>> {
    let Some(req_bytes) = read_request_head(&mut stream).await else {
        return Ok(None);
    };
    let req = String::from_utf8_lossy(&req_bytes);
    let first_line = req.lines().next().unwrap_or("");
    // GET /?code=...&state=... HTTP/1.1
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let query = path.split_once('?').map(|x| x.1).unwrap_or("");
    let (code, state, error) = parse_callback_query(query);
    let body = if code.is_some() {
        "<html><body style=\"font-family:sans-serif;padding:4rem;text-align:center\">\
         <h2>Comail is connected.</h2><p>You can close this tab.</p></body></html>"
    } else {
        "<html><body style=\"font-family:sans-serif;padding:4rem;text-align:center\">\
         <h2>Sign-in failed.</h2><p>Return to Comail and try again.</p></body></html>"
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;

    if let Some(e) = error {
        tracing::warn!(error = %e, "oauth: provider redirected back with an error");
        return Err(CoreError::Auth(format!("oauth error: {e}")));
    }
    if let Some(code) = code {
        return Ok(Some(AuthCode { code, state }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn_waiter(server: LoopbackServer) -> tokio::task::JoinHandle<Result<AuthCode>> {
        tokio::spawn(async move { server.wait_for_code(Duration::from_secs(30)).await })
    }

    async fn get(port: u16, target: &str) {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
    }

    #[test]
    fn callback_query_decoding_never_panics() {
        // Hostile inputs that panicked the old byte-indexed decoder or would
        // mangle values. All must decode losslessly or literally — never panic.
        let cases = [
            "code=%a%C3%A9%zz&state=s", // invalid escapes + multi-byte UTF-8
            "code=%",                   // truncated escape
            "code=%2",                  // truncated escape
            "code=a%2Bb+c%25d&state=x", // encoded '+', '+' as space, '%'
            "code=%FF%FE&state=y",      // invalid UTF-8 bytes
            "code=+ab%0A%0D&state=z",   // leading '+', CR/LF bytes
            "code",
            "",
            "?",
            "code==x&&state==",
        ];
        for q in cases {
            let _ = parse_callback_query(q);
        }
        // '+' is form-decoded to a space — a leading '+' must not reach the
        // code value raw, and never parses as hex like the old decoder tried.
        let (code, state, _) = parse_callback_query("code=a+b&state=%2Bst");
        assert_eq!(code.as_deref(), Some("a b"));
        assert_eq!(state.as_deref(), Some("+st"));
        // Properly percent-encoded UTF-8 decodes.
        let (code, _, _) = parse_callback_query("code=%C3%A9");
        assert_eq!(code.as_deref(), Some("é"));
    }

    #[tokio::test]
    async fn silent_connection_does_not_block_the_real_redirect() {
        let server = LoopbackServer::bind().await.unwrap();
        let port = server.port;
        let waiter = spawn_waiter(server);
        // A speculative preconnect that never sends a request must not stall
        // acceptance of the real redirect (the old code awaited it inline).
        let _silent = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        get(port, "/?code=abc&state=xyz").await;
        let code = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(code.code, "abc");
        assert_eq!(code.state.as_deref(), Some("xyz"));
    }

    #[tokio::test]
    async fn request_split_across_writes_is_reassembled() {
        let server = LoopbackServer::bind().await.unwrap();
        let port = server.port;
        let waiter = spawn_waiter(server);
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        // The request line arrives in two TCP segments; a single `read`
        // (the old code) would truncate the query.
        s.write_all(b"GET /?code=split&sta").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        s.write_all(b"te=xy HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let code = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(code.code, "split");
        assert_eq!(code.state.as_deref(), Some("xy"));
    }

    #[tokio::test]
    async fn oauth_error_aborts_the_wait() {
        let server = LoopbackServer::bind().await.unwrap();
        let port = server.port;
        let waiter = spawn_waiter(server);
        get(port, "/?error=access_denied&state=s").await;
        let res = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .unwrap()
            .unwrap();
        let err = res.err().expect("oauth error should abort the wait");
        assert!(err.to_string().contains("access_denied"));
    }
}
