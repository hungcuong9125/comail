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
    /// The lock serializing all refresh-token grants for one account. Entries
    /// are created lazily and kept for the life of the provider (bounded by
    /// the number of accounts ever seen): dropping an entry while a grant is
    /// in flight would give the next caller a *different* mutex and break the
    /// serialization.
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

    /// Store initial tokens after the auth-code exchange.
    pub async fn store_initial(
        &self,
        account_id: i64,
        access_token: String,
        expires_in: Option<i64>,
        refresh_token: Option<String>,
    ) -> Result<()> {
        if let Some(rt) = refresh_token {
            credentials::store_async(account_id, Slot::RefreshToken, rt).await?;
        }
        // A new token set replaces the previous grant wholesale: drop the old
        // primary token AND every scoped token minted under it, then record
        // the new one.
        self.forget(account_id).await;
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

    /// Drop every cached token - primary and scoped - for the account. Waits
    /// on the account's refresh lock so a just-finishing grant can't insert a
    /// token *after* the clear and resurrect it.
    pub async fn forget(&self, account_id: i64) {
        let lock = self.refresh_lock(account_id).await;
        let _permit = lock.lock().await;
        self.cache.lock().await.remove(&account_id);
        self.scoped
            .lock()
            .await
            .retain(|(a, _), _| *a != account_id);
    }

    /// A valid access token, refreshed if less than 5 minutes remain.
    pub async fn access_token(&self, account_id: i64, provider: Provider) -> Result<String> {
        if let Some(tok) = self.cache.lock().await.get(&account_id)
            && Self::fresh(tok)
        {
            return Ok(tok.access_token.clone());
        }
        // Serialize the refresh per account: a concurrent caller queues here
        // and re-checks instead of spending the rotated refresh token a second
        // time (`invalid_grant` -> spurious needs-reauth). The cache-map locks
        // are only ever held for lookups; the network call below happens under
        // the per-account lock alone.
        let lock = self.refresh_lock(account_id).await;
        let _permit = lock.lock().await;
        if let Some(tok) = self.cache.lock().await.get(&account_id)
            && Self::fresh(tok)
        {
            return Ok(tok.access_token.clone());
        }
        let refreshed = self.refresh(account_id, provider).await?;
        self.cache
            .lock()
            .await
            .insert(account_id, refreshed.clone());
        Ok(refreshed.access_token)
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
        let key = (account_id, scope.to_string());
        if let Some(tok) = self.scoped.lock().await.get(&key)
            && Self::fresh(tok)
        {
            return Ok(tok.access_token.clone());
        }
        let lock = self.refresh_lock(account_id).await;
        let _permit = lock.lock().await;
        if let Some(tok) = self.scoped.lock().await.get(&key)
            && Self::fresh(tok)
        {
            return Ok(tok.access_token.clone());
        }
        let cfg =
            for_provider(provider).ok_or_else(|| CoreError::Auth("not an oauth account".into()))?;
        let (client_id, client_secret) = crate::oauth::providers::resolve_credentials(provider)?;
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

        let body = post_form(cfg.token_url, &form).await?;
        let tok: TokenResponse = serde_json::from_str(&body).map_err(|_| {
            // invalid_grant / consent_required => the scope was never granted.
            if body.contains("invalid_grant") || body.contains("AADSTS65001") {
                CoreError::NeedsReauth
            } else {
                CoreError::Auth(format!("scoped token request failed: {body}"))
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

    async fn refresh(&self, account_id: i64, provider: Provider) -> Result<CachedToken> {
        let cfg =
            for_provider(provider).ok_or_else(|| CoreError::Auth("not an oauth account".into()))?;
        let (client_id, client_secret) = crate::oauth::providers::resolve_credentials(provider)?;
        let refresh_token = credentials::load_async(account_id, Slot::RefreshToken).await?;

        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token),
            ("client_id".to_string(), client_id),
        ];
        if let Some(cs) = client_secret {
            form.push(("client_secret".to_string(), cs));
        }

        let body = post_form(cfg.token_url, &form).await?;
        let tok: TokenResponse = serde_json::from_str(&body).map_err(|_| {
            if body.contains("invalid_grant") {
                CoreError::NeedsReauth
            } else {
                CoreError::Auth(format!("token refresh failed: {body}"))
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

/// Form POST to an OAuth token endpoint. Returns the raw response body on ANY
/// HTTP status — callers parse both success and OAuth-error JSON out of it
/// (`invalid_grant` in a 4xx body is what maps to `NeedsReauth`); only
/// transport failures are `Err`.
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
async fn post_form_inner(url: &str, form: &[(String, String)]) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent("comail-oauth/0.1")
        .build()
        .map_err(|e| CoreError::Network(format!("token POST http client: {e}")))?;
    let mut resp = client
        .post(url)
        .form(form)
        .send()
        .await
        .inspect_err(|e| tracing::warn!(%url, error = %e, "oauth: token POST failed"))
        .map_err(|e| CoreError::Network(format!("token POST {url}: {e}")))?;
    // No `.error_for_status()`: a non-2xx status still carries the OAuth error
    // JSON the caller needs.
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
    async fn forget_drops_primary_and_scoped_tokens() {
        let p = TokenProvider::new();
        p.store_initial(1, "tok".to_string(), Some(3600), None)
            .await
            .unwrap();
        p.scoped.lock().await.insert(
            (1, "scope".into()),
            CachedToken {
                access_token: "scoped".into(),
                expires_at_ms: i64::MAX,
            },
        );
        p.scoped.lock().await.insert(
            (2, "scope".into()),
            CachedToken {
                access_token: "other".into(),
                expires_at_ms: i64::MAX,
            },
        );
        p.forget(1).await;
        assert!(p.cache.lock().await.is_empty());
        let scoped = p.scoped.lock().await;
        assert_eq!(scoped.len(), 1);
        assert!(scoped.contains_key(&(2, "scope".into())));
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
}
