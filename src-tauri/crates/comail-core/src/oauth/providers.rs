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

/// Client credentials the user entered in Settings: the client id, plus a
/// legacy inline secret kept only until the startup migration moves it into
/// the OS keyring (and only while the keyring stays unavailable). Refreshed
/// on startup and whenever settings change; env vars still take precedence
/// at resolve time.
fn configured() -> &'static RwLock<HashMap<Provider, (String, Option<String>)>> {
    static MAP: OnceLock<RwLock<HashMap<Provider, (String, Option<String>)>>> = OnceLock::new();
    MAP.get_or_init(Default::default)
}

pub fn set_configured(provider: Provider, client_id: &str, legacy_secret: Option<&str>) {
    let mut map = configured().write().unwrap();
    let id = client_id.trim();
    if id.is_empty() {
        map.remove(&provider);
    } else {
        let secret = legacy_secret
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        map.insert(provider, (id.to_string(), secret));
    }
}

/// (client_id, client_secret) for an OAuth provider: env vars first, then
/// the client id configured in Settings with the secret read from the OS
/// keyring. A not-yet-migrated inline secret (keyring unavailable since the
/// upgrade) remains usable as the fallback so sign-in is never broken.
pub async fn resolve_credentials(provider: Provider) -> Result<(String, Option<String>)> {
    let cfg = for_provider(provider)
        .ok_or_else(|| CoreError::Auth("provider does not use oauth".into()))?;
    if let Ok(id) = std::env::var(cfg.client_id_env) {
        return Ok((id, std::env::var(cfg.client_secret_env).ok()));
    }
    let (id, legacy) = configured()
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
    let secret = match client_secret_slot(provider) {
        Some(slot) => credentials::load_async(0, slot).await.ok().or(legacy),
        None => legacy,
    };
    Ok((id, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_uses_configured_values_and_clears() {
        // Microsoft: no env vars set in the test environment. The keyring may
        // or may not hold a real secret on a dev machine, so assertions only
        // pin what must hold either way; the keyring path itself is covered
        // by the oauth_secrets integration tests under the insecure file.
        set_configured(Provider::Microsoft, "  ms-id  ", None);
        let (id, _) = resolve_credentials(Provider::Microsoft).await.unwrap();
        assert_eq!(id, "ms-id");

        set_configured(Provider::Microsoft, "ms-id", Some("  s3cret "));
        let (_, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
        // Keyring value wins when present; otherwise the legacy copy serves.
        assert!(secret.is_some());

        // Empty id clears the registration entirely.
        set_configured(Provider::Microsoft, "", Some("whatever"));
        assert!(resolve_credentials(Provider::Microsoft).await.is_err());
    }

    #[tokio::test]
    async fn resolve_rejects_non_oauth_provider() {
        assert!(resolve_credentials(Provider::Imap).await.is_err());
    }
}
