//! Access-token lifecycle for OAuth accounts. `access_token` hands the mail
//! sync a live token, refreshing ~5 min before expiry. `store_initial` saves
//! the first grant right after the auth-code exchange. `refresh` runs the
//! `refresh_token` grant and stores the rotated refresh token providers send
//! back (Microsoft rotates every use; Google occasionally). The refresh token
//! itself lives in the OS keyring; access tokens are cached in memory only —
//! deliberately NOT written to the keyring: nothing ever reads them back (a
//! restart just refreshes), and a Microsoft access-token JWT is large enough
//! to blow past the Windows Credential Manager blob limit (~2560 bytes).
//!
//! Refresh tokens are single-use: each grant invalidates the previous refresh
//! token. Two overlapping grants for the same account would therefore race —
//! the loser submits the already-consumed token, the provider answers
//! `invalid_grant`, and the account is wrongly flagged needs-reauth. Every
//! refresh-token use (the mail grant and the extra-scope grants like Microsoft
//! Graph) is serialized under one per-account mutex for that reason. The
//! per-account map of locks is deliberately separate from the token caches:
//! network I/O happens only under an account's own lock, so one slow token
//! endpoint can never stall another account's cached-token reads (the old
//! single cache-wide lock was held across the network call).

use crate::accounts::credentials::{self, Slot};
use crate::error::{CoreError, Result};
use crate::models::Provider;
use crate::oauth::providers::for_provider;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct CachedToken {
    access_token: String,
    expires_at_ms: i64,
}

#[derive(Clone, Default)]
pub struct TokenProvider {
    /// Primary (mail-audience) access tokens by account.
    cache: Arc<Mutex<HashMap<i64, CachedToken>>>,
    /// Extra-scope (e.g. Microsoft Graph) access tokens by (account, scope).
    /// Scoped grants used to be un-cached and un-locked: every caller ran its
    /// own refresh, which both hammered the token endpoint and raced the
    /// primary grant for the rotating refresh token.
    scoped: Arc<Mutex<HashMap<(i64, String), CachedToken>>>,
    /// The lock serializing all refresh-token work for one account — primary
    /// and scoped grants, `store_initial`, and `purge` each run their ENTIRE
    /// operation under it, so the stored refresh token can never be read,
    /// rotated, replaced, or deleted between a grant's start and its writes.
    /// Entries are created lazily and kept for the life of the provider
    /// (bounded by the number of accounts ever seen): dropping an entry while
    /// a grant is in flight would give the next caller a *different* mutex
    /// and break the serialization.
    refresh_locks: Arc<Mutex<HashMap<i64, Arc<Mutex<()>>>>>,
}

impl TokenProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// The lock serializing refresh-token grants for `account_id`.
    async fn refresh_lock(&self, account_id: i64) -> Arc<Mutex<()>> {
        self.refresh_locks
            .lock()
            .await
            .entry(account_id)
            .or_default()
            .clone()
    }

    /// Fresh enough to serve? Refresh when less than 5 minutes remain.
    fn fresh(tok: &CachedToken) -> bool {
        tok.expires_at_ms - crate::models::now_ms() > 5 * 60 * 1000
    }

    /// A fresh cached primary token, or `None` when missing/stale.
    async fn cached(&self, account_id: i64) -> Option<String> {
        let cache = self.cache.lock().await;
        cache
            .get(&account_id)
            .filter(|t| Self::fresh(t))
            .map(|t| t.access_token.clone())
    }

    /// A fresh cached scoped token, or `None` when missing/stale.
    async fn cached_scoped(&self, key: &(i64, String)) -> Option<String> {
        let scoped = self.scoped.lock().await;
        scoped
            .get(key)
            .filter(|t| Self::fresh(t))
            .map(|t| t.access_token.clone())
    }

    /// Clear both caches for the account. Caller must hold the account lock —
    /// `purge` and `store_initial` use this.
    async fn clear_caches(&self, account_id: i64) {
        self.cache.lock().await.remove(&account_id);
        self.scoped
            .lock()
            .await
            .retain(|(a, _), _| *a != account_id);
    }

    /// Store initial tokens after the auth-code exchange.
    ///
    /// The whole operation — persisting the new refresh token, clearing the
    /// old caches, inserting the new token — runs under the account lock: a
    /// grant still in flight for the *old* token set completes first (its
    /// writes are superseded by the clear+insert below), and callers queued
    /// behind this find the fresh cache entry on their re-check instead of
    /// spending the already-consumed refresh token again.
    pub async fn store_initial(
        &self,
        account_id: i64,
        access_token: String,
        expires_in: Option<i64>,
        refresh_token: Option<String>,
    ) -> Result<()> {
        let lock = self.refresh_lock(account_id).await;
        let _permit = lock.lock().await;
        if let Some(rt) = refresh_token {
            credentials::store_async(account_id, Slot::RefreshToken, rt).await?;
        }
        // A new token set replaces the previous grant wholesale: drop the old
        // primary token AND every scoped token minted under it, then record
        // the new one.
        self.clear_caches(account_id).await;
        let expires_at_ms =
            crate::models::now_ms() + expires_in.unwrap_or(3600).saturating_sub(60) * 1000;
        self.cache.lock().await.insert(
            account_id,
            CachedToken {
                access_token,
                expires_at_ms,
            },
        );
        Ok(())
    }

    /// Atomically delete the account's credentials and cached tokens under
    /// the account's refresh lock — used on account removal. A grant in
    /// flight completes first and its writes are then erased below; a grant
    /// queued behind the purge finds no stored refresh token and fails with
    /// `Auth("no stored credential")` before touching the network.
    pub async fn purge(&self, account_id: i64) {
        let lock = self.refresh_lock(account_id).await;
        let _permit = lock.lock().await;
        // `delete_all` is a blocking keyring call — the same spawn_blocking
        // pattern the crate uses for store_async/load_async. Holding the
        // account lock across it is what makes delete+clear atomic wrt grants.
        let _ = tokio::task::spawn_blocking(move || credentials::delete_all(account_id)).await;
        self.clear_caches(account_id).await;
    }

    /// A valid access token, refreshed if less than 5 minutes remain.
    pub async fn access_token(&self, account_id: i64, provider: Provider) -> Result<String> {
        let cfg =
            for_provider(provider).ok_or_else(|| CoreError::Auth("not an oauth account".into()))?;
        self.access_token_inner(account_id, provider, cfg.token_url)
            .await
    }

    /// `access_token` against a specific token endpoint — tests only; the
    /// provider's `token_url` is a fixed constant in production.
    #[cfg(test)]
    async fn access_token_at(
        &self,
        account_id: i64,
        provider: Provider,
        token_url: &str,
    ) -> Result<String> {
        self.access_token_inner(account_id, provider, token_url)
            .await
    }

    /// Fast path = a cache read without the account lock. Slow path = the
    /// whole grant under the account's lock: cache re-check, refresh-token
    /// load, POST, rotated-token persist, cache write. `token_url` is a
    /// parameter only so tests can point it at a local listener.
    async fn access_token_inner(
        &self,
        account_id: i64,
        provider: Provider,
        token_url: &str,
    ) -> Result<String> {
        if let Some(tok) = self.cached(account_id).await {
            return Ok(tok);
        }
        // Serialize the refresh per account: a concurrent caller queues here
        // and re-checks instead of spending the rotated refresh token a second
        // time (`invalid_grant` -> spurious needs-reauth). The cache-map locks
        // are only ever held for lookups; the network call below happens under
        // the per-account lock alone.
        let lock = self.refresh_lock(account_id).await;
        let _permit = lock.lock().await;
        if let Some(tok) = self.cached(account_id).await {
            return Ok(tok);
        }
        let refreshed = self.refresh(account_id, provider, token_url).await?;
        let token = refreshed.access_token.clone();
        self.cache.lock().await.insert(account_id, refreshed);
        Ok(token)
    }

    /// Mint an access token for a *specific* resource scope (e.g. Microsoft
    /// Graph), separate from the cached mail token. Microsoft issues
    /// single-resource tokens, so the mail token cannot be reused against
    /// `graph.microsoft.com`; this runs a dedicated refresh-token grant with an
    /// explicit `scope` and returns the resulting (Graph-audience) token
    /// without disturbing the mail cache or the stored mail access token.
    ///
    /// The refresh token may be rotated by this grant; the new one is persisted
    /// (it stays multi-resource, so mail refresh keeps working). A rejected
    /// grant usually means the extra scope was never consented, surfaced as
    /// `NeedsReauth` so the caller can trigger incremental consent. Scoped
    /// tokens are cached per (account, scope) with the same expiry skew as the
    /// primary token, and the grant is serialized with the primary grant on
    /// the account's refresh lock because both consume (and rotate) the same
    /// refresh token.
    pub async fn access_token_for_scope(
        &self,
        account_id: i64,
        provider: Provider,
        scope: &str,
    ) -> Result<String> {
        let cfg =
            for_provider(provider).ok_or_else(|| CoreError::Auth("not an oauth account".into()))?;
        self.access_token_for_scope_inner(account_id, provider, scope, cfg.token_url)
            .await
    }

    /// `access_token_for_scope` against a specific token endpoint — tests
    /// only; the provider's `token_url` is a fixed constant in production.
    #[cfg(test)]
    async fn access_token_for_scope_at(
        &self,
        account_id: i64,
        provider: Provider,
        scope: &str,
        token_url: &str,
    ) -> Result<String> {
        self.access_token_for_scope_inner(account_id, provider, scope, token_url)
            .await
    }

    /// Same fast/slow split as `access_token_inner`: the whole scoped grant
    /// runs under the account's lock, shared with the primary grant because
    /// both consume (and rotate) the same refresh token.
    async fn access_token_for_scope_inner(
        &self,
        account_id: i64,
        provider: Provider,
        scope: &str,
        token_url: &str,
    ) -> Result<String> {
        let key = (account_id, scope.to_string());
        if let Some(tok) = self.cached_scoped(&key).await {
            return Ok(tok);
        }
        let lock = self.refresh_lock(account_id).await;
        let _permit = lock.lock().await;
        if let Some(tok) = self.cached_scoped(&key).await {
            return Ok(tok);
        }
        let (client_id, client_secret) =
            crate::oauth::providers::resolve_credentials(provider).await?;
        let refresh_token = credentials::load_async(account_id, Slot::RefreshToken).await?;

        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token),
            ("client_id".to_string(), client_id),
            // offline_access keeps a (rotated) refresh token coming back.
            ("scope".to_string(), format!("{scope} offline_access")),
        ];
        if let Some(cs) = client_secret {
            form.push(("client_secret".to_string(), cs));
        }

        let body = post_form(token_url, &form).await?;
        let tok: TokenResponse = serde_json::from_str(&body).map_err(|_| {
            // invalid_grant / consent_required => the scope was never granted.
            if body.contains("invalid_grant") || body.contains("AADSTS65001") {
                CoreError::NeedsReauth
            } else {
                CoreError::Auth(format!(
                    "scoped token request failed: {}",
                    err_excerpt(&body)
                ))
            }
        })?;

        // Do NOT overwrite Slot::AccessToken (that is the mail token, a
        // different audience). Only persist the rotated refresh token.
        if let Some(rt) = tok.refresh_token {
            credentials::store_async(account_id, Slot::RefreshToken, rt).await?;
        }
        let cached = CachedToken {
            access_token: tok.access_token,
            expires_at_ms: crate::models::now_ms()
                + tok.expires_in.unwrap_or(3600).saturating_sub(60) * 1000,
        };
        let token = cached.access_token.clone();
        self.scoped.lock().await.insert(key, cached);
        Ok(token)
    }

    /// Run the mail refresh-token grant. Caller holds the account lock.
    async fn refresh(
        &self,
        account_id: i64,
        provider: Provider,
        token_url: &str,
    ) -> Result<CachedToken> {
        let (client_id, client_secret) =
            crate::oauth::providers::resolve_credentials(provider).await?;
        let refresh_token = credentials::load_async(account_id, Slot::RefreshToken).await?;

        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token),
            ("client_id".to_string(), client_id),
        ];
        if let Some(cs) = client_secret {
            form.push(("client_secret".to_string(), cs));
        }

        let body = post_form(token_url, &form).await?;
        let tok: TokenResponse = serde_json::from_str(&body).map_err(|_| {
            if body.contains("invalid_grant") {
                CoreError::NeedsReauth
            } else {
                CoreError::Auth(format!("token refresh failed: {}", err_excerpt(&body)))
            }
        })?;

        if let Some(rt) = tok.refresh_token {
            credentials::store_async(account_id, Slot::RefreshToken, rt).await?;
        }
        Ok(CachedToken {
            access_token: tok.access_token,
            expires_at_ms: crate::models::now_ms()
                + tok.expires_in.unwrap_or(3600).saturating_sub(60) * 1000,
        })
    }
}

/// Bound how much of a token-endpoint body ever reaches an error message.
/// OAuth error bodies are small JSON, but a misconfigured or hostile
/// endpoint can return up to `POST_FORM_MAX_BODY`, and an unexpected body
/// could carry tokens. 240 chars is plenty for an OAuth error JSON.
fn err_excerpt(body: &str) -> String {
    const MAX: usize = 240;
    let body = body.trim();
    match body.char_indices().nth(MAX) {
        Some((i, _)) => format!("{}…", &body[..i]),
        None => body.to_string(),
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// Upper bound for one token-endpoint exchange (connect + TLS + request +
/// response). The token endpoint normally answers in well under a second;
/// 30s only absorbs pathological networks while still surfacing "endpoint
/// silently dropped the connection" instead of hanging a sync forever.
const POST_FORM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Token responses are a small JSON object; cap the accepted body so a broken
/// or hostile endpoint can't exhaust memory.
const POST_FORM_MAX_BODY: u64 = 256 * 1024;

/// Form POST to an OAuth token endpoint. Returns the raw response body for
/// 2xx and 4xx statuses — callers parse both success and OAuth-error JSON out
/// of it (`invalid_grant` in a 4xx body is what maps to `NeedsReauth`).
/// 5xx, 429, redirects, and transport failures surface as `CoreError::Network`
/// — all are transient/network-level problems, not auth failures, and mapping
/// them `Auth` would flag healthy accounts needs-reauth during an outage or a
/// captive-portal redirect.
///
/// Bounded by `POST_FORM_TIMEOUT`: it wraps the whole exchange, so a stalled
/// connect, a server that never responds, and a server that accepts then goes
/// silent all surface as a `CoreError::Network` timeout instead of an
/// unbounded hang.
pub async fn post_form(url: &str, form: &[(String, String)]) -> Result<String> {
    tokio::time::timeout(POST_FORM_TIMEOUT, post_form_inner(url, form))
        .await
        .map_err(|_| {
            tracing::warn!(%url, "oauth: token POST: timed out after 30s");
            CoreError::Network(format!("token POST {url}: timed out"))
        })?
}

/// The HTTP exchange behind [`post_form`]. reqwest (rustls + webpki roots,
/// same as the rest of the crate) replaces the old hand-rolled HTTP/1.1-over-
/// TcpStream client, which sent `Connection: close` but couldn't de-chunk the
/// response, ignored the status, and extracted JSON by brace-matching.
///
/// Proxy behaviour (reqwest 0.12.28 with this crate's feature set):
/// `auto_sys_proxy` is on by default, so the standard env vars `HTTP_PROXY`,
/// `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` are honoured (hyper-util's
/// `Matcher::from_system` reads them, skipping env proxies when
/// `REQUEST_METHOD` is set — the CGI guard). The OS-configured proxy — e.g.
/// macOS System Settings — is NOT read: that requires reqwest's
/// `system-proxy`/`macos-system-configuration` features, which are off.
async fn post_form_inner(url: &str, form: &[(String, String)]) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("comail-oauth/0.1")
        // Never follow redirects: reqwest would re-POST the form — refresh
        // token and client secret included — to the redirect target on a
        // 307/308, possibly another host or plain http.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| CoreError::Network(format!("token POST http client: {e}")))?;
    let mut resp = client
        .post(url)
        .form(form)
        .send()
        .await
        .inspect_err(|e| tracing::warn!(%url, error = %e, "oauth: token POST failed"))
        .map_err(|e| CoreError::Network(format!("token POST {url}: {e}")))?;
    let status = resp.status();
    if status.is_redirection() {
        // Redirects are disabled above, so the response reaches us as-is. A
        // 3xx on a token endpoint means a captive portal, proxy interference,
        // or a misconfigured endpoint — transient/network-level, NOT an auth
        // failure: `Auth` would flag a healthy account needs-reauth.
        tracing::warn!(%url, %status, "oauth: token POST: unexpected redirect");
        return Err(CoreError::Network(format!(
            "token POST {url}: unexpected redirect (HTTP {status})"
        )));
    }
    if status.is_server_error() || status.as_u16() == 429 {
        // 5xx / 429 are provider-side failures: transient, not an auth
        // problem. The body — often an HTML error page — is dropped unread;
        // it carries nothing the caller can map and would only pollute the
        // error message.
        tracing::warn!(%url, %status, "oauth: token POST: server-side failure");
        return Err(CoreError::Network(format!(
            "token POST {url}: HTTP {status}"
        )));
    }
    // No `.error_for_status()`: a 4xx status still carries the OAuth error
    // JSON the caller needs to map to NeedsReauth.
    if resp
        .content_length()
        .is_some_and(|len| len > POST_FORM_MAX_BODY)
    {
        tracing::warn!(%url, "oauth: token POST: oversized response");
        return Err(CoreError::Network(format!(
            "token POST {url}: oversized response"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CoreError::Network(format!("token POST {url}: read failed: {e}")))?
    {
        if body.len() as u64 + chunk.len() as u64 > POST_FORM_MAX_BODY {
            tracing::warn!(%url, "oauth: token POST: oversized response");
            return Err(CoreError::Network(format!(
                "token POST {url}: oversized response"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve one HTTP response on a loopback listener. Returns the endpoint
    /// URL plus a handle that resolves to the raw request bytes received.
    async fn serve_once(
        status: &str,
        headers: &str,
        body: &str,
    ) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (status, headers, body) = (status.to_string(), headers.to_string(), body.to_string());
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            // Drain the request: headers and body can arrive in separate TCP
            // segments, so read until the peer goes briefly idle.
            let mut req = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    s.read(&mut chunk),
                )
                .await
                {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => req.extend_from_slice(&chunk[..n]),
                    Ok(Err(e)) => panic!("request read failed: {e}"),
                }
            }
            let resp = format!("HTTP/1.1 {status}\r\n{headers}\r\n\r\n{body}");
            s.write_all(resp.as_bytes()).await.unwrap();
            s.shutdown().await.unwrap();
            req
        });
        (format!("http://127.0.0.1:{port}/token"), task)
    }

    fn form() -> Vec<(String, String)> {
        vec![
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), "rt 123+&".into()),
        ]
    }

    #[tokio::test]
    async fn post_form_posts_urlencoded_and_returns_200_body() {
        let (url, server) = serve_once(
            "200 OK",
            "Content-Type: application/json\r\nContent-Length: 38",
            "{\"access_token\":\"tok\",\"expires_in\":3599}",
        )
        .await;
        let body = post_form(&url, &form()).await.unwrap();
        assert!(body.contains("\"access_token\":\"tok\""));
        let req = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(req.starts_with("POST /token HTTP/1.1"));
        assert!(req.contains("content-type: application/x-www-form-urlencoded"));
        assert!(req.contains("grant_type=refresh_token"));
        // Value characters that must be encoded are (space as `+`, `+`/`&`
        // percent-encoded).
        assert!(req.contains("refresh_token=rt+123%2B%26"));
    }

    #[tokio::test]
    async fn post_form_returns_oauth_error_body_on_400() {
        // The `invalid_grant` -> `NeedsReauth` mapping lives in callers reading
        // this body; a non-2xx status must not become a transport error.
        let (url, _server) = serve_once(
            "400 Bad Request",
            "Content-Type: application/json",
            "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been revoked.\"}",
        )
        .await;
        let body = post_form(&url, &form()).await.unwrap();
        assert!(body.contains("invalid_grant"), "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn post_form_decodes_chunked_response() {
        // Chunk boundaries inside the JSON used to break the old client.
        let chunked = "5\r\n{\"acc\r\n6\r\ness_to\r\nB\r\nken\":\"tok\"}\r\n0\r\n\r\n";
        let (url, _server) = serve_once(
            "200 OK",
            "Content-Type: application/json\r\nTransfer-Encoding: chunked",
            chunked,
        )
        .await;
        let body = post_form(&url, &form()).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["access_token"], "tok");
    }

    #[tokio::test]
    async fn cached_token_is_served_without_a_grant() {
        let p = TokenProvider::new();
        p.store_initial(1, "tok".to_string(), Some(3600), None)
            .await
            .unwrap();
        assert_eq!(p.access_token(1, Provider::Gmail).await.unwrap(), "tok");
    }

    #[tokio::test]
    async fn purge_drops_primary_and_scoped_tokens() {
        let _creds = creds_env().await;
        let p = TokenProvider::new();
        p.store_initial(91_005, "tok".to_string(), Some(3600), None)
            .await
            .unwrap();
        p.scoped.lock().await.insert(
            (91_005, "scope".into()),
            CachedToken {
                access_token: "scoped".into(),
                expires_at_ms: i64::MAX,
            },
        );
        p.scoped.lock().await.insert(
            (91_006, "scope".into()),
            CachedToken {
                access_token: "other".into(),
                expires_at_ms: i64::MAX,
            },
        );
        p.purge(91_005).await;
        assert!(p.cache.lock().await.is_empty());
        let scoped = p.scoped.lock().await;
        assert_eq!(scoped.len(), 1);
        assert!(scoped.contains_key(&(91_006, "scope".into())));
    }

    #[tokio::test]
    async fn one_accounts_grant_does_not_block_anothers_cached_token() {
        let p = TokenProvider::new();
        p.store_initial(2, "tok2".to_string(), Some(3600), None)
            .await
            .unwrap();
        // Hold account 1's refresh lock (as an in-flight grant would): a
        // cached-token read for account 2 must still return immediately.
        let lock = p.refresh_lock(1).await;
        let _held = lock.lock().await;
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            p.access_token(2, Provider::Gmail),
        )
        .await;
        assert_eq!(res.unwrap().unwrap(), "tok2");
    }

    #[tokio::test]
    async fn waiting_caller_rechecks_cache_instead_of_regranting() {
        let p = TokenProvider::new();
        // Account 1's grant is "in flight".
        let lock = p.refresh_lock(1).await;
        let held = lock.lock().await;
        let p2 = p.clone();
        let waiter = tokio::spawn(async move { p2.access_token(1, Provider::Gmail).await });
        tokio::task::yield_now().await;
        // The grant completes: a fresh token lands in the cache.
        p.cache.lock().await.insert(
            1,
            CachedToken {
                access_token: "fresh".into(),
                expires_at_ms: i64::MAX,
            },
        );
        drop(held);
        // The queued caller sees it and returns without any network grant.
        assert_eq!(waiter.await.unwrap().unwrap(), "fresh");
    }

    #[tokio::test]
    async fn post_form_returns_4xx_oauth_error_bodies() {
        // Other OAuth errors (400) and a bare 401 stay on the caller's
        // body-parsing path, same as invalid_grant.
        for (status, body) in [
            ("400 Bad Request", "{\"error\":\"temporarily_unavailable\"}"),
            ("401 Unauthorized", "{\"error\":\"unauthorized_client\"}"),
        ] {
            let (url, _s) = serve_once(status, "Content-Type: application/json", body).await;
            assert_eq!(post_form(&url, &form()).await.unwrap(), body);
        }
        // Empty body is returned as-is; the caller's JSON parse fails it.
        let (url, _s) = serve_once("200 OK", "Content-Length: 0", "").await;
        assert_eq!(post_form(&url, &form()).await.unwrap(), "");
    }

    #[tokio::test]
    async fn post_form_maps_429_and_5xx_to_network_error() {
        // Provider-side failures are transient, not auth problems: they must
        // not come back as `Auth` (sync would flag the account needs-reauth).
        for (status, body) in [
            ("429 Too Many Requests", "rate limited"),
            (
                "500 Internal Server Error",
                "<html><body><h1>upstream exploded</h1></body></html>",
            ),
        ] {
            let (url, _s) = serve_once(status, "Content-Type: text/html", body).await;
            let err = post_form(&url, &form()).await.unwrap_err();
            assert!(
                matches!(err, CoreError::Network(_)),
                "{status} mapped to {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn post_form_rejects_oversized_body() {
        // An announced body larger than the cap is rejected without reading.
        let (url, _s) = serve_once(
            "200 OK",
            &format!(
                "Content-Type: application/json\r\nContent-Length: {}",
                POST_FORM_MAX_BODY + 1
            ),
            "",
        )
        .await;
        let err = post_form(&url, &form()).await.unwrap_err();
        assert!(matches!(err, CoreError::Network(_)), "{err:?}");
    }

    #[tokio::test]
    async fn post_form_does_not_follow_redirects() {
        // A token endpoint answering 3xx must not make the client re-POST the
        // form (refresh token, client secret) to the redirect target.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = listener.local_addr().unwrap().port();
        let target_hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target_hit2 = target_hit.clone();
        let target = tokio::spawn(async move {
            if let Ok(Ok((mut s, _))) =
                tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept()).await
            {
                target_hit2.store(true, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\n{\"access_token\":\"hijack\"}",
                )
                .await
                .unwrap();
            }
        });
        let (url, _s) = serve_once(
            "307 Temporary Redirect",
            &format!("Location: http://127.0.0.1:{target_port}/token\r\nContent-Length: 0"),
            "",
        )
        .await;
        let err = post_form(&url, &form()).await.unwrap_err();
        // A captive-portal/proxy redirect is transient, not an auth failure
        // (`Auth` would flag the healthy account needs-reauth).
        assert!(matches!(err, CoreError::Network(_)), "{err:?}");
        target.await.unwrap();
        assert!(
            !target_hit.load(std::sync::atomic::Ordering::SeqCst),
            "redirect target received the form"
        );
    }

    /// Route credential storage to a per-process temp file and register OAuth
    /// client creds, so grant paths run end-to-end in tests. Returns a guard
    /// serializing every credential-touching test: the insecure-file backend
    /// is a shared read-modify-write JSON file, so parallel tests would
    /// otherwise clobber each other's stored refresh tokens. No other unit
    /// test touches credentials; distinct account ids isolate the file.
    async fn creds_env() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let guard = LOCK.lock().await;
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let path = std::env::temp_dir().join(format!(
                "comail-tokens-test-creds-{}.json",
                std::process::id()
            ));
            unsafe { std::env::set_var("COMAIL_CREDENTIALS_INSECURE_FILE", path) };
        });
        crate::oauth::providers::set_configured(Provider::Gmail, "test-client-id", None);
        guard
    }

    /// A local token endpoint: accepts one POST per canned response,
    /// returns it as JSON, and records every request body. Returns the
    /// endpoint URL and a handle resolving to the captured bodies.
    async fn grant_endpoint(
        responses: Vec<String>,
        delay: std::time::Duration,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut bodies = Vec::new();
            for resp in responses {
                let (mut s, _) = listener.accept().await.unwrap();
                // Drain the request: headers and body can arrive in separate
                // TCP segments, so read until the peer goes briefly idle.
                let mut req = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(200),
                        s.read(&mut chunk),
                    )
                    .await
                    {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(n)) => req.extend_from_slice(&chunk[..n]),
                        Ok(Err(e)) => panic!("request read failed: {e}"),
                    }
                }
                let text = String::from_utf8_lossy(&req);
                bodies.push(text.split("\r\n\r\n").nth(1).unwrap_or("").to_string());
                tokio::time::sleep(delay).await;
                let out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    resp.len(),
                    resp
                );
                s.write_all(out.as_bytes()).await.unwrap();
                s.shutdown().await.unwrap();
            }
            bodies
        });
        (format!("http://127.0.0.1:{port}/token"), task)
    }

    /// Form-decoded value of one field in a captured request body.
    fn form_field(body: &str, name: &str) -> String {
        url::form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn store_initial_supersedes_a_grant_still_in_flight() {
        let _creds = creds_env().await;
        let acct = 91_001;
        credentials::store_async(acct, Slot::RefreshToken, "rt0".into())
            .await
            .unwrap();
        // Slow endpoint: the grant is mid-POST when store_initial arrives.
        let (url, server) = grant_endpoint(
            vec![
                "{\"access_token\":\"AT-old\",\"refresh_token\":\"rt1\",\"expires_in\":3600}"
                    .into(),
            ],
            std::time::Duration::from_millis(300),
        )
        .await;
        let p = TokenProvider::new();
        let p2 = p.clone();
        let url2 = url.clone();
        let refresh =
            tokio::spawn(async move { p2.access_token_at(acct, Provider::Gmail, &url2).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        p.store_initial(acct, "AT-new".into(), Some(3600), Some("rt-new".into()))
            .await
            .unwrap();
        // The in-flight grant completed first and returned its own valid
        // token; nobody saw NeedsReauth.
        assert_eq!(refresh.await.unwrap().unwrap(), "AT-old");
        // The stored refresh token and caches are the NEW grant's.
        assert_eq!(
            credentials::load_async(acct, Slot::RefreshToken)
                .await
                .unwrap(),
            "rt-new"
        );
        assert_eq!(p.cached(acct).await.as_deref(), Some("AT-new"));
        assert!(p.scoped.lock().await.is_empty());
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn purge_erases_credentials_and_caches_after_an_in_flight_grant() {
        let _creds = creds_env().await;
        let acct = 91_002;
        credentials::store_async(acct, Slot::RefreshToken, "rt0".into())
            .await
            .unwrap();
        let (url, server) = grant_endpoint(
            vec![
                "{\"access_token\":\"AT-old\",\"refresh_token\":\"rt1\",\"expires_in\":3600}"
                    .into(),
            ],
            std::time::Duration::from_millis(300),
        )
        .await;
        let p = TokenProvider::new();
        let p2 = p.clone();
        let url2 = url.clone();
        let refresh =
            tokio::spawn(async move { p2.access_token_at(acct, Provider::Gmail, &url2).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        p.purge(acct).await;
        // The grant finished first and got its token; then everything was
        // erased atomically under the same lock.
        assert_eq!(refresh.await.unwrap().unwrap(), "AT-old");
        assert!(p.cached(acct).await.is_none());
        assert!(p.scoped.lock().await.is_empty());
        assert!(
            credentials::load_async(acct, Slot::RefreshToken)
                .await
                .is_err()
        );
        // A grant queued behind the purge finds no refresh token and fails
        // before any network call.
        let err = p
            .access_token_at(acct, Provider::Gmail, &url)
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Auth(_)), "{err:?}");
        assert_eq!(server.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn primary_and_scoped_grants_share_the_rotating_refresh_token() {
        let _creds = creds_env().await;
        let acct = 91_003;
        credentials::store_async(acct, Slot::RefreshToken, "rt0".into())
            .await
            .unwrap();
        let (url, server) = grant_endpoint(
            vec![
                "{\"access_token\":\"A1\",\"refresh_token\":\"rt1\",\"expires_in\":3600}".into(),
                "{\"access_token\":\"A2\",\"refresh_token\":\"rt2\",\"expires_in\":3600}".into(),
            ],
            std::time::Duration::ZERO,
        )
        .await;
        let p = TokenProvider::new();
        let (primary, scoped) = tokio::join!(
            p.access_token_at(acct, Provider::Gmail, &url),
            p.access_token_for_scope_at(acct, Provider::Gmail, "scope", &url),
        );
        primary.unwrap();
        scoped.unwrap();
        let bodies = server.await.unwrap();
        assert_eq!(bodies.len(), 2);
        // Exactly sequential: the second grant submitted the refresh token
        // rotated by the first — a parallel grant would have resubmitted rt0
        // and been invalidated.
        let rts: Vec<String> = bodies
            .iter()
            .map(|b| form_field(b, "refresh_token"))
            .collect();
        assert_eq!(rts, ["rt0", "rt1"]);
        assert_eq!(
            credentials::load_async(acct, Slot::RefreshToken)
                .await
                .unwrap(),
            "rt2"
        );
    }

    #[tokio::test]
    async fn two_concurrent_primary_grants_post_once() {
        let _creds = creds_env().await;
        let acct = 91_004;
        credentials::store_async(acct, Slot::RefreshToken, "rt0".into())
            .await
            .unwrap();
        let (url, server) = grant_endpoint(
            vec!["{\"access_token\":\"AT\",\"refresh_token\":\"rt1\",\"expires_in\":3600}".into()],
            std::time::Duration::from_millis(100),
        )
        .await;
        let p = TokenProvider::new();
        let (a, b) = tokio::join!(
            p.access_token_at(acct, Provider::Gmail, &url),
            p.access_token_at(acct, Provider::Gmail, &url),
        );
        assert_eq!(a.unwrap(), "AT");
        // The queued caller re-checked the cache instead of posting again.
        assert_eq!(b.unwrap(), "AT");
        assert_eq!(server.await.unwrap().len(), 1);
    }
}
