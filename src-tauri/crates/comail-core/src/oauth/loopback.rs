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

    /// Wait for the OAuth redirect carrying `?code=...&state=<expected_state>`
    /// (or `?error=...`). Each accepted connection runs on its own task under
    /// a short read deadline: browsers routinely open speculative connections
    /// that send nothing, and awaiting one inline would block the real
    /// redirect until the outer timeout. Outstanding handler tasks are
    /// aborted when this returns — on success, error, or timeout.
    ///
    /// `expected_state` is the value sent to the provider: a request carrying
    /// `code`/`error` whose state does not match is a stray or forged local
    /// request — it gets a neutral rejection and the wait continues, so a
    /// forged local request can neither end the sign-in early nor see the
    /// "connected" page.
    pub async fn wait_for_code(self, expected_state: &str, timeout: Duration) -> Result<AuthCode> {
        /// Bound on concurrent connection handlers. While `MAX_CONNS` are
        /// active we simply stop accepting — new connections wait in the
        /// kernel backlog until a handler finishes — so 16 idle local sockets
        /// can't get the real browser redirect accepted-and-closed.
        const MAX_CONNS: usize = 16;
        let expected: std::sync::Arc<str> = std::sync::Arc::from(expected_state);
        // JoinSet aborts every outstanding task on drop — so returning (or
        // the outer timeout dropping `fut`) cancels the handlers.
        let mut tasks = tokio::task::JoinSet::new();
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
                    }, if tasks.len() < MAX_CONNS => {
                        let (stream, _) = accept?;
                        let expected = expected.clone();
                        tasks.spawn(async move { handle_connection(stream, &expected).await });
                    }
                    msg = tasks.join_next(), if !tasks.is_empty() => match msg {
                        // The real redirect: done.
                        Some(Ok(Ok(Some(code)))) => return Ok(code),
                        // OAuth error: abort sign-in.
                        Some(Ok(Err(e))) => return Err(e),
                        // A handler panicked: surface it rather than hanging.
                        Some(Err(e)) if e.is_panic() => {
                            return Err(CoreError::Other(format!("oauth loopback task: {e}")));
                        }
                        // A speculative/garbage/state-mismatched connection
                        // was dropped; or a handler was cancelled.
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
/// carrying a code and the expected state, `Err` if the provider redirected
/// back with an error (also state-checked), and `Ok(None)` for connections
/// we should ignore (dropped/speculative/stray requests — browsers also fire
/// `GET /favicon.ico` at localhost pages — or OAuth-looking requests whose
/// state does not match).
async fn handle_connection(
    mut stream: TcpStream,
    expected_state: &str,
) -> Result<Option<AuthCode>> {
    let Some(req_bytes) = read_request_head(&mut stream).await else {
        return Ok(None);
    };
    let req = String::from_utf8_lossy(&req_bytes);
    let first_line = req.lines().next().unwrap_or("");
    // GET /?code=...&state=... HTTP/1.1
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let query = path.split_once('?').map(|x| x.1).unwrap_or("");
    let (code, state, error) = parse_callback_query(query);
    // A request carrying an OAuth response must echo the exact `state` we
    // sent. Anything else — a stray request that happens to have a `code`, or
    // a forged local request — is rejected with a neutral 400 and the wait
    // continues: it must neither end the sign-in early nor be shown the
    // "connected" page.
    if (code.is_some() || error.is_some()) && state.as_deref() != Some(expected_state) {
        tracing::warn!("oauth: loopback callback with wrong state ignored");
        let body = "<html><body><h2>Bad request.</h2></body></html>";
        let resp = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
        return Ok(None);
    }
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

    fn spawn_waiter(
        server: LoopbackServer,
        expected_state: &'static str,
    ) -> tokio::task::JoinHandle<Result<AuthCode>> {
        tokio::spawn(async move {
            server
                .wait_for_code(expected_state, Duration::from_secs(30))
                .await
        })
    }

    /// Send a request and return the response head (status line included).
    async fn get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
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
        let waiter = spawn_waiter(server, "xyz");
        // A speculative preconnect that never sends a request must not stall
        // acceptance of the real redirect (the old code awaited it inline).
        let _silent = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let resp = get(port, "/?code=abc&state=xyz").await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
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
        let waiter = spawn_waiter(server, "xy");
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
        let waiter = spawn_waiter(server, "s");
        get(port, "/?error=access_denied&state=s").await;
        let res = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .unwrap()
            .unwrap();
        let err = res.err().expect("oauth error should abort the wait");
        assert!(err.to_string().contains("access_denied"));
    }

    #[tokio::test]
    async fn wrong_state_code_is_rejected_then_real_redirect_succeeds() {
        // A forged local request with a `code` but the wrong state must not
        // end the sign-in: it gets a neutral 400 and the wait continues.
        let server = LoopbackServer::bind().await.unwrap();
        let port = server.port;
        let waiter = spawn_waiter(server, "good");
        let resp = get(port, "/?code=forged&state=evil").await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(!waiter.is_finished(), "wrong-state callback ended the wait");
        let resp = get(port, "/?code=real&state=good").await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let code = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(code.code, "real");
    }

    #[tokio::test]
    async fn wrong_state_error_does_not_end_the_wait() {
        // Same for the error form: `?error=` carrying a wrong state is a
        // stray/forged request, not the provider's answer.
        let server = LoopbackServer::bind().await.unwrap();
        let port = server.port;
        let waiter = spawn_waiter(server, "good");
        let resp = get(port, "/?error=access_denied&state=evil").await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
        assert!(!waiter.is_finished(), "wrong-state error ended the wait");
        get(port, "/?code=real&state=good").await;
        let code = tokio::time::timeout(Duration::from_secs(3), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(code.code, "real");
    }

    #[tokio::test]
    async fn connections_beyond_the_cap_wait_in_the_backlog() {
        // With every handler slot busy, further connections are simply not
        // accepted — the real redirect must survive in the kernel backlog
        // until a silent connection's deadline frees a slot.
        let server = LoopbackServer::bind().await.unwrap();
        let port = server.port;
        let waiter = spawn_waiter(server, "good");
        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(TcpStream::connect(("127.0.0.1", port)).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The redirect's request is already buffered; it is answered as soon
        // as a silent conn's CONN_DEADLINE frees a handler (not dropped like
        // the old accept-and-close).
        let mut real = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        real.write_all(b"GET /?code=real&state=good HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let code = tokio::time::timeout(Duration::from_secs(10), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(code.code, "real");
        drop(held);
    }
}
