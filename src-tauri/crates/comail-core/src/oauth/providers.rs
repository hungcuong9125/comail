use crate::accounts::credentials::{self, Slot};
use crate::error::{CoreError, Result};
use crate::models::Provider;

/// Incremental-consent scope for Google Calendar (CalDAV access). Not in
/// the default GOOGLE scopes: mail-only accounts should not be asked for it.
pub const GOOGLE_CALENDAR_SCOPE: &str = "https://www.googleapis.com/auth/calendar";

/// Incremental-consent scope (Microsoft Graph) for creating Teams meetings.
/// Kept out of the default MICROSOFT scopes: those all target
/// `outlook.office.com`, and Microsoft issues a single-resource access token,
/// so mixing a `graph.microsoft.com` scope into the mail token would break the
/// IMAP/SMTP audience. It is consented separately and redeemed for its own
/// Graph-audience token (see `TokenProvider::access_token_for_scope`).
pub const MS_ONLINE_MEETINGS_SCOPE: &str = "https://graph.microsoft.com/OnlineMeetings.ReadWrite";

/// Incremental-consent scope (Microsoft Graph) for writing events into the
/// user's Outlook / Microsoft 365 calendar, so events created in the app show
/// up in Outlook and Teams. Same single-resource caveat as the meetings scope.
pub const MS_CALENDARS_SCOPE: &str = "https://graph.microsoft.com/Calendars.ReadWrite";
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

pub struct OAuthProviderConfig {
    pub auth_url: &'static str,
    pub token_url: &'static str,
    pub scopes: &'static [&'static str],
    /// Env var names let users supply their own app registrations.
    pub client_id_env: &'static str,
    pub client_secret_env: &'static str,
}

pub const GOOGLE: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://accounts.google.com/o/oauth2/v2/auth",
    token_url: "https://oauth2.googleapis.com/token",
    // mail.google.com is the only scope Google accepts for IMAP/SMTP XOAUTH2.
    // `profile` adds the user's name to the id_token, used as the sender name.
    scopes: &["https://mail.google.com/", "openid", "email", "profile"],
    client_id_env: "COMAIL_GOOGLE_CLIENT_ID",
    client_secret_env: "COMAIL_GOOGLE_CLIENT_SECRET",
};

pub const MICROSOFT: OAuthProviderConfig = OAuthProviderConfig {
    auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    scopes: &[
        "https://outlook.office.com/IMAP.AccessAsUser.All",
        "https://outlook.office.com/SMTP.Send",
        "offline_access",
        "openid",
        "email",
        "profile",
    ],
    client_id_env: "COMAIL_MS_CLIENT_ID",
    client_secret_env: "COMAIL_MS_CLIENT_SECRET",
};

pub fn for_provider(p: Provider) -> Option<&'static OAuthProviderConfig> {
    match p {
        Provider::Gmail => Some(&GOOGLE),
        Provider::Microsoft => Some(&MICROSOFT),
        Provider::Imap => None,
    }
}

/// The keyring slot holding `provider`'s user-supplied client secret — an
/// app-level secret stored under account id 0, like the AI key.
pub fn client_secret_slot(provider: Provider) -> Option<Slot> {
    match provider {
        Provider::Gmail => Some(Slot::GoogleClientSecret),
        Provider::Microsoft => Some(Slot::MsClientSecret),
        Provider::Imap => None,
    }
}

/// The last known state of `provider`'s keyring-held client secret. Cached
/// in memory — refreshed by the startup migration and `set_oauth_client_secret`
/// — so token grants and `get_settings` never touch the OS keyring.
#[derive(Clone)]
pub enum SecretState {
    /// No secret is stored (or the provider was never probed).
    Unset,
    /// The keyring holds this value.
    Value(String),
    /// The credential store errored on the last probe — a transient store
    /// problem, NOT "no secret". Must not be treated as an absent secret:
    /// a token request sent without `client_secret` would come back as an
    /// auth error and flag the account `needs_reauth`.
    Unavailable,
}

impl std::fmt::Debug for SecretState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretState::Unset => f.write_str("Unset"),
            SecretState::Value(_) => f.write_str("Value(***)"),
            SecretState::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// Client credentials the user entered in Settings: the client id, the
/// cached keyring secret state, and a legacy inline copy kept only until the
/// startup migration moves it into the OS keyring (usable while the keyring
/// stays unavailable). Refreshed on startup and whenever settings change;
/// env vars still take precedence at resolve time.
#[derive(Clone)]
pub struct Configured {
    pub id: String,
    pub legacy: Option<String>,
    pub secret: SecretState,
}

impl std::fmt::Debug for Configured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Configured")
            .field("id", &self.id)
            .field("legacy", &self.legacy.as_ref().map(|_| "***"))
            .field("secret", &self.secret)
            .finish()
    }
}

/// One provider's cache slot: the configured credentials plus when the last
/// `Unavailable` probe ran — the rate limiter for re-probes.
struct ProviderEntry {
    configured: Configured,
    unavailable_since: Option<Instant>,
}

fn configured() -> &'static RwLock<HashMap<Provider, ProviderEntry>> {
    static MAP: OnceLock<RwLock<HashMap<Provider, ProviderEntry>>> = OnceLock::new();
    MAP.get_or_init(Default::default)
}

/// Whether a usable secret exists per provider, tracked independently of the
/// resolver entry — a secret stored before its client ID still counts (the
/// entry is dropped when the id is empty, but the flag and Clear button
/// should not vanish).
fn secret_presence() -> &'static RwLock<HashMap<Provider, bool>> {
    static MAP: OnceLock<RwLock<HashMap<Provider, bool>>> = OnceLock::new();
    MAP.get_or_init(Default::default)
}

/// How long an `Unavailable` outcome suppresses re-probes. Long enough that
/// a persistently broken keyring is not hit on every token refresh, short
/// enough that an unlocked keychain recovers without an app restart.
const DEFAULT_REPROBE_INTERVAL: Duration = Duration::from_secs(30);

fn reprobe_interval_cell() -> &'static RwLock<Duration> {
    static INTERVAL: OnceLock<RwLock<Duration>> = OnceLock::new();
    INTERVAL.get_or_init(|| RwLock::new(DEFAULT_REPROBE_INTERVAL))
}

/// Override the `Unavailable` re-probe interval (test support).
pub fn set_reprobe_interval(interval: Duration) {
    *reprobe_interval_cell().write().unwrap() = interval;
}

/// One re-probe at a time per provider; waiters re-check before probing.
fn reprobe_lock(provider: Provider) -> &'static tokio::sync::Mutex<()> {
    static GMAIL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static MS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static OTHER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    match provider {
        Provider::Gmail => &GMAIL,
        Provider::Microsoft => &MS,
        Provider::Imap => &OTHER,
    }
}

fn mark_presence(provider: Provider, c: &Configured) {
    let present = matches!(c.secret, SecretState::Value(_)) || c.legacy.is_some();
    secret_presence().write().unwrap().insert(provider, present);
}

pub fn set_configured(
    provider: Provider,
    client_id: &str,
    legacy: Option<&str>,
    secret: SecretState,
) {
    let entry = Configured {
        id: client_id.trim().to_string(),
        legacy: legacy
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        secret,
    };
    let mut map = configured().write().unwrap();
    if entry.id.is_empty() {
        // Drop the resolver entry but leave the presence flag: a secret
        // stored before its client ID still exists in the keyring.
        map.remove(&provider);
    } else {
        mark_presence(provider, &entry);
        map.insert(
            provider,
            ProviderEntry {
                // A fresh Unavailable was just probed by the caller — the
                // rate limit starts now.
                unavailable_since: matches!(entry.secret, SecretState::Unavailable)
                    .then(Instant::now),
                configured: entry,
            },
        );
    }
}

/// The cached secret state for `provider`, if the resolver knows about it.
pub fn cached_secret_state(provider: Provider) -> Option<SecretState> {
    configured()
        .read()
        .unwrap()
        .get(&provider)
        .map(|e| e.configured.secret.clone())
}

/// Drop every cached entry and presence flag (test support — the cache is a
/// process-global because `TokenProvider` and the flow code resolve without
/// a `Core` instance).
pub fn reset_provider_config() {
    configured().write().unwrap().clear();
    secret_presence().write().unwrap().clear();
}

/// Read `provider`'s client secret from the keyring once, distinguishing a
/// real store error from "no entry" (unlike the insecure-file backend, which
/// cannot). Called only when the cache needs (re)populating.
pub async fn probe_secret(provider: Provider) -> SecretState {
    match client_secret_slot(provider) {
        Some(slot) => match credentials::try_load_async(0, slot).await {
            Ok(Some(secret)) => SecretState::Value(secret),
            Ok(None) => SecretState::Unset,
            Err(_) => SecretState::Unavailable,
        },
        None => SecretState::Unset,
    }
}

/// Whether the user has a client secret configured for `provider` — the key
/// behind the `has*ClientSecret` IPC flags. Reads only the in-memory cache.
pub fn has_client_secret(provider: Provider) -> bool {
    secret_presence()
        .read()
        .unwrap()
        .get(&provider)
        .copied()
        .unwrap_or(false)
}

/// Record the presence flag directly — used by `set_oauth_client_secret`,
/// which always knows the truth even when the provider has no client ID yet
/// (and so has no resolver entry for `apply` to update the flag through).
pub fn set_secret_presence(provider: Provider, present: bool) {
    secret_presence().write().unwrap().insert(provider, present);
}

/// The cached state is `Unavailable` and the rate limit allows a re-probe.
fn unavailable_due(provider: Provider) -> bool {
    let map = configured().read().unwrap();
    match map.get(&provider) {
        Some(e) if matches!(e.configured.secret, SecretState::Unavailable) => e
            .unavailable_since
            .map(|t| t.elapsed() >= *reprobe_interval_cell().read().unwrap())
            .unwrap_or(true),
        _ => false,
    }
}

/// Heal an `Unavailable` cache entry: re-probe the keyring (via the blocking
/// credential API, never on the runtime's threads), at most once per
/// interval and single-flight per provider. If the store now answers empty
/// while a legacy row copy is still cached, the pending migration completes
/// right here — the row key itself is stripped by the next
/// `migrate_oauth_client_secrets` pass.
async fn reprobe_unavailable(provider: Provider) {
    let _permit = reprobe_lock(provider).lock().await;
    // A waiter may have healed the entry while we queued for the lock.
    if !unavailable_due(provider) {
        return;
    }
    if let Some(e) = configured().write().unwrap().get_mut(&provider) {
        e.unavailable_since = Some(Instant::now());
    }
    let mut state = probe_secret(provider).await;
    let mut migrated_legacy = false;
    if matches!(state, SecretState::Unset) {
        let pending = configured()
            .read()
            .unwrap()
            .get(&provider)
            .and_then(|e| e.configured.legacy.clone());
        if let (Some(value), Some(slot)) = (pending, client_secret_slot(provider)) {
            let verified = credentials::store_async(0, slot, value.clone())
                .await
                .is_ok()
                && matches!(
                    credentials::try_load_async(0, slot).await,
                    Ok(Some(back)) if back == value
                );
            if verified {
                state = SecretState::Value(value);
                migrated_legacy = true;
            }
        }
    }
    if let Some(e) = configured().write().unwrap().get_mut(&provider) {
        e.configured.secret = state.clone();
        if migrated_legacy {
            e.configured.legacy = None;
        }
        if !matches!(state, SecretState::Unavailable) {
            e.unavailable_since = None;
        }
        let c = e.configured.clone();
        mark_presence(provider, &c);
    }
}

/// (client_id, client_secret) for an OAuth provider: env vars first, then
/// the client id configured in Settings with the secret served from the
/// in-memory cache the migration/`set_oauth_client_secret` maintain. A stale
/// `Unavailable` is re-probed (rate-limited, single-flight) so an unlocked
/// keychain recovers without a restart; while still down it falls back to a
/// not-yet-migrated inline copy, or fails as a transient `Keyring` error
/// that sync treats as retryable — never `needs_reauth`.
pub async fn resolve_credentials(provider: Provider) -> Result<(String, Option<String>)> {
    let cfg = for_provider(provider)
        .ok_or_else(|| CoreError::Auth("provider does not use oauth".into()))?;
    if let Ok(id) = std::env::var(cfg.client_id_env) {
        return Ok((id, std::env::var(cfg.client_secret_env).ok()));
    }
    if unavailable_due(provider) {
        reprobe_unavailable(provider).await;
    }
    let c = configured()
        .read()
        .unwrap()
        .get(&provider)
        .map(|e| e.configured.clone())
        .ok_or_else(|| {
            CoreError::Auth(format!(
                "no OAuth app configured for {}: add a client ID in Settings → Accounts, or set {}",
                provider.as_str(),
                cfg.client_id_env
            ))
        })?;
    match c.secret {
        SecretState::Value(secret) => Ok((c.id, Some(secret))),
        SecretState::Unset => Ok((c.id, c.legacy)),
        SecretState::Unavailable => match c.legacy {
            Some(legacy) => Ok((c.id, Some(legacy))),
            None => Err(CoreError::Keyring(format!(
                "OS keyring unavailable while reading the {} OAuth client secret",
                provider.as_str()
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_uses_configured_values_and_clears() {
        set_configured(Provider::Microsoft, "  ms-id  ", None, SecretState::Unset);
        let (id, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
        assert_eq!(id, "ms-id");
        assert_eq!(secret, None);

        // The cached keyring value wins over a pending legacy copy.
        set_configured(
            Provider::Microsoft,
            "ms-id",
            Some("old"),
            SecretState::Value("new".into()),
        );
        assert_eq!(
            resolve_credentials(Provider::Microsoft).await.unwrap().1,
            Some("new".into())
        );

        // No entry: the legacy copy serves while a migration is pending.
        set_configured(
            Provider::Microsoft,
            "ms-id",
            Some("  s3cret "),
            SecretState::Unset,
        );
        assert_eq!(
            resolve_credentials(Provider::Microsoft).await.unwrap().1,
            Some("s3cret".into())
        );

        // Keyring error: legacy copy serves; without one it is a transient
        // Keyring error — never Auth/NeedsReauth (which sync would flag).
        set_configured(
            Provider::Microsoft,
            "ms-id",
            Some("s3cret"),
            SecretState::Unavailable,
        );
        assert_eq!(
            resolve_credentials(Provider::Microsoft).await.unwrap().1,
            Some("s3cret".into())
        );
        set_configured(Provider::Microsoft, "ms-id", None, SecretState::Unavailable);
        // A fresh Unavailable is rate-limited from re-probing immediately, so
        // this deterministically errors without touching the keyring.
        assert!(matches!(
            resolve_credentials(Provider::Microsoft).await,
            Err(CoreError::Keyring(_))
        ));

        // Empty id clears the registration entirely.
        set_configured(
            Provider::Microsoft,
            "",
            Some("whatever"),
            SecretState::Unset,
        );
        assert!(resolve_credentials(Provider::Microsoft).await.is_err());
    }

    #[tokio::test]
    async fn resolve_rejects_non_oauth_provider() {
        assert!(resolve_credentials(Provider::Imap).await.is_err());
    }

    #[test]
    fn has_secret_flag_matches_cache() {
        reset_provider_config();
        set_configured(Provider::Gmail, "g-id", None, SecretState::Unset);
        assert!(!has_client_secret(Provider::Gmail));
        set_configured(Provider::Gmail, "g-id", Some("pending"), SecretState::Unset);
        assert!(has_client_secret(Provider::Gmail));
        set_configured(
            Provider::Gmail,
            "g-id",
            None,
            SecretState::Value("s".into()),
        );
        assert!(has_client_secret(Provider::Gmail));
        // A secret stored before its client ID still reports "stored": an
        // empty id drops the resolver entry but leaves the flag.
        set_configured(Provider::Gmail, "", None, SecretState::Value("s".into()));
        assert!(has_client_secret(Provider::Gmail));
        // Clearing goes through set_oauth_client_secret, which flags it.
        set_secret_presence(Provider::Gmail, false);
        assert!(!has_client_secret(Provider::Gmail));
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let c = Configured {
            id: "id".into(),
            legacy: Some("legacy-secret".into()),
            secret: SecretState::Value("live-secret".into()),
        };
        let out = format!("{c:?} {:?}", c.secret);
        assert!(out.contains("***"));
        assert!(!out.contains("legacy-secret"));
        assert!(!out.contains("live-secret"));
    }
}
