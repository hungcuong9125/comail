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
#[derive(Debug, Clone)]
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

/// Client credentials the user entered in Settings: the client id, the
/// cached keyring secret state, and a legacy inline copy kept only until the
/// startup migration moves it into the OS keyring (usable while the keyring
/// stays unavailable). Refreshed on startup and whenever settings change;
/// env vars still take precedence at resolve time.
#[derive(Debug, Clone)]
pub struct Configured {
    pub id: String,
    pub legacy: Option<String>,
    pub secret: SecretState,
}

fn configured() -> &'static RwLock<HashMap<Provider, Configured>> {
    static MAP: OnceLock<RwLock<HashMap<Provider, Configured>>> = OnceLock::new();
    MAP.get_or_init(Default::default)
}

pub fn set_configured(
    provider: Provider,
    client_id: &str,
    legacy: Option<&str>,
    secret: SecretState,
) {
    let mut map = configured().write().unwrap();
    let id = client_id.trim();
    if id.is_empty() {
        map.remove(&provider);
    } else {
        map.insert(
            provider,
            Configured {
                id: id.to_string(),
                legacy: legacy
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                secret,
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
        .map(|c| c.secret.clone())
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
    configured()
        .read()
        .unwrap()
        .get(&provider)
        .map(|c| matches!(c.secret, SecretState::Value(_)) || c.legacy.is_some())
        .unwrap_or(false)
}

/// (client_id, client_secret) for an OAuth provider: env vars first, then
/// the client id configured in Settings with the secret served from the
/// in-memory cache the migration/`set_oauth_client_secret` maintain — token
/// grants never read the keyring. A keyring probe failure (`Unavailable`)
/// falls back to a not-yet-migrated inline copy, or fails as a transient
/// `Keyring` error that sync treats as retryable — never `needs_reauth`.
pub fn resolve_credentials(provider: Provider) -> Result<(String, Option<String>)> {
    let cfg = for_provider(provider)
        .ok_or_else(|| CoreError::Auth("provider does not use oauth".into()))?;
    if let Ok(id) = std::env::var(cfg.client_id_env) {
        return Ok((id, std::env::var(cfg.client_secret_env).ok()));
    }
    let c = configured()
        .read()
        .unwrap()
        .get(&provider)
        .cloned()
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

    #[test]
    fn resolve_uses_configured_values_and_clears() {
        set_configured(Provider::Microsoft, "  ms-id  ", None, SecretState::Unset);
        let (id, secret) = resolve_credentials(Provider::Microsoft).unwrap();
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
            resolve_credentials(Provider::Microsoft).unwrap().1,
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
            resolve_credentials(Provider::Microsoft).unwrap().1,
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
            resolve_credentials(Provider::Microsoft).unwrap().1,
            Some("s3cret".into())
        );
        set_configured(Provider::Microsoft, "ms-id", None, SecretState::Unavailable);
        assert!(matches!(
            resolve_credentials(Provider::Microsoft),
            Err(CoreError::Keyring(_))
        ));

        // Empty id clears the registration entirely.
        set_configured(
            Provider::Microsoft,
            "",
            Some("whatever"),
            SecretState::Unset,
        );
        assert!(resolve_credentials(Provider::Microsoft).is_err());
    }

    #[test]
    fn resolve_rejects_non_oauth_provider() {
        assert!(resolve_credentials(Provider::Imap).is_err());
    }

    #[test]
    fn has_secret_flag_matches_cache() {
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
        set_configured(Provider::Gmail, "", None, SecretState::Unset);
        assert!(!has_client_secret(Provider::Gmail));
    }
}
