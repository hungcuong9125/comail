//! User-supplied OAuth client secrets (Google / Microsoft app registrations)
//! live in the OS keyring — the COMAIL_CREDENTIALS_INSECURE_FILE backend here —
//! never in the settings row or across IPC. These tests run the real startup
//! migration, resolver, and settings commands end to end.
//!
//! The env var is process-global, so every test that touches credentials
//! serializes on CREDS_LOCK; the file path is switched per test while the
//! guard is held.

use comail_core::Core;
use comail_core::accounts::credentials::{self, Slot};
use comail_core::config::Paths;
use comail_core::db::{Db, repo};
use comail_core::models::{Provider, Settings};
use comail_core::oauth::providers::resolve_credentials;
use std::path::Path;

static CREDS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Point the insecure-file credential backend at `path` and hold the guard
/// serializing every credential-touching test.
async fn creds_env(path: &Path) -> tokio::sync::MutexGuard<'static, ()> {
    let guard = CREDS_LOCK.lock().await;
    // SAFETY: the guard serializes every use of the shared backend file.
    unsafe { std::env::set_var("COMAIL_CREDENTIALS_INSECURE_FILE", path) };
    guard
}

/// The pre-keyring settings row: both client secrets inline. Written through
/// `repo::settings::set`, whose legacy-key carry-forward produces exactly the
/// JSON shape an old build left behind.
async fn seed_legacy_settings(db: &Db) {
    db.write(|conn| {
        let mut s = repo::settings::get(conn)?;
        s.google_client_id = "g-id".into();
        s.ms_client_id = "ms-id".into();
        s.google_client_secret = "g-secret".into();
        s.ms_client_secret = "ms-secret".into();
        repo::settings::set(conn, &s)
    })
    .await
    .unwrap();
}

/// The raw settings JSON, for asserting which keys the row still carries.
async fn row_json(db: &Db) -> serde_json::Value {
    db.read(|conn| {
        Ok(conn
            .query_row(
                "SELECT value FROM app_settings WHERE key = 'settings'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default())
    })
    .await
    .unwrap()
}

fn paths(tmp: &tempfile::TempDir) -> Paths {
    let paths = Paths::for_tests(tmp.path());
    paths.ensure().unwrap();
    paths
}

/// A settings row holding both secrets migrates to the credential store on
/// startup: the row is stripped, get_settings reports flags only, and the
/// resolver serves the keyring values.
#[tokio::test(flavor = "multi_thread")]
async fn migration_moves_secrets_to_keyring() {
    let tmp = tempfile::tempdir().unwrap();
    let _guard = creds_env(&tmp.path().join("credentials.json")).await;
    let db = Db::open(&paths(&tmp).db_file()).unwrap();
    seed_legacy_settings(&db).await;

    let core = Core::start(paths(&tmp)).await.unwrap();

    // Values landed in the credential store...
    assert_eq!(
        credentials::load(0, Slot::GoogleClientSecret).unwrap(),
        "g-secret"
    );
    assert_eq!(
        credentials::load(0, Slot::MsClientSecret).unwrap(),
        "ms-secret"
    );
    // ...and the row no longer carries them.
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());
    assert!(json.get("msClientSecret").is_none());
    assert_eq!(json["googleClientId"], "g-id");

    // get_settings reports presence flags only - the values never cross IPC.
    let settings = core.get_settings().await.unwrap();
    assert!(settings.has_google_client_secret);
    assert!(settings.has_ms_client_secret);
    let wire = serde_json::to_string(&settings).unwrap();
    assert!(!wire.contains("g-secret"));
    assert!(!wire.contains("ms-secret"));
    assert!(!wire.contains("googleClientSecret"));
    assert!(!wire.contains("msClientSecret"));

    // The OAuth config resolver returns the keyring values.
    let (id, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(id, "g-id");
    assert_eq!(secret.as_deref(), Some("g-secret"));
    let (id, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
    assert_eq!(id, "ms-id");
    assert_eq!(secret.as_deref(), Some("ms-secret"));

    // A second migration pass is a no-op.
    core.migrate_oauth_client_secrets().await;
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());
    assert!(json.get("msClientSecret").is_none());
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("g-secret"));
}

/// When the keyring write fails (the file backend pointed at a directory
/// stands in for a locked keychain), the row keeps its secrets and sign-in
/// still works through the resolver's fallback. A later retry migrates.
#[tokio::test(flavor = "multi_thread")]
async fn failed_keyring_write_keeps_row_secret_working() {
    let tmp = tempfile::tempdir().unwrap();
    let broken = tmp.path().join("creds-is-a-dir");
    std::fs::create_dir(&broken).unwrap();
    let db = Db::open(&paths(&tmp).db_file()).unwrap();
    seed_legacy_settings(&db).await;

    let core;
    {
        let _guard = creds_env(&broken).await;
        core = Core::start(paths(&tmp)).await.unwrap();

        // Row untouched: the migration refused to drop the only copy.
        let json = row_json(&db).await;
        assert_eq!(json["googleClientSecret"], "g-secret");
        assert_eq!(json["msClientSecret"], "ms-secret");

        // The legacy copy still signs in, and the flag still reports "set".
        let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
        assert_eq!(secret.as_deref(), Some("g-secret"));
        let (_, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
        assert_eq!(secret.as_deref(), Some("ms-secret"));
        let settings = core.get_settings().await.unwrap();
        assert!(settings.has_google_client_secret);
        assert!(settings.has_ms_client_secret);
        let wire = serde_json::to_string(&settings).unwrap();
        assert!(!wire.contains("g-secret"));

        // Even a whole-object settings write while the keyring is down keeps
        // the row copy instead of wiping it.
        let mut s = core.get_settings().await.unwrap();
        s.theme = "carbon".into();
        core.set_settings(s).await.unwrap();
        let json = row_json(&db).await;
        assert_eq!(json["googleClientSecret"], "g-secret");
        assert_eq!(json["msClientSecret"], "ms-secret");
    }

    // Keyring back (next start): the pending secrets migrate across.
    let _guard = creds_env(&tmp.path().join("credentials.json")).await;
    core.migrate_oauth_client_secrets().await;
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());
    assert!(json.get("msClientSecret").is_none());
    assert_eq!(
        credentials::load(0, Slot::GoogleClientSecret).unwrap(),
        "g-secret"
    );
    let (_, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
    assert_eq!(secret.as_deref(), Some("ms-secret"));
}

/// A settings write carrying no secret fields (the frontend shape) must not
/// clear the stored secrets, and set_oauth_client_secret replaces/clears them.
#[tokio::test(flavor = "multi_thread")]
async fn settings_write_never_clears_stored_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let _guard = creds_env(&tmp.path().join("credentials.json")).await;
    let db = Db::open(&paths(&tmp).db_file()).unwrap();
    seed_legacy_settings(&db).await;
    let core = Core::start(paths(&tmp)).await.unwrap();

    // Whole-object write from the new shape: flags only, no secret values.
    let mut s: Settings = core.get_settings().await.unwrap();
    s.theme = "carbon".into();
    core.set_settings(s).await.unwrap();
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("g-secret"));
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());

    // set_oauth_client_secret replaces the value in the keyring...
    core.set_oauth_client_secret("google".into(), "new-secret".into())
        .await
        .unwrap();
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("new-secret"));
    // ...and clears it (flag flips, nothing falls back to an old copy).
    core.set_oauth_client_secret("google".into(), String::new())
        .await
        .unwrap();
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret, None);
    assert!(!core.get_settings().await.unwrap().has_google_client_secret);
    // Microsoft is untouched.
    let (_, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
    assert_eq!(secret.as_deref(), Some("ms-secret"));
}

/// A pre-keyring client that still submits the secret inline via set_settings
/// gets it moved to the keyring rather than persisted or dropped.
#[tokio::test(flavor = "multi_thread")]
async fn inline_secret_in_settings_write_migrates() {
    let tmp = tempfile::tempdir().unwrap();
    let _guard = creds_env(&tmp.path().join("credentials.json")).await;
    let db = Db::open(&paths(&tmp).db_file()).unwrap();
    db.write(|conn| {
        let mut s = repo::settings::get(conn)?;
        s.google_client_id = "g-id".into();
        repo::settings::set(conn, &s)
    })
    .await
    .unwrap();
    let core = Core::start(paths(&tmp)).await.unwrap();

    let mut s = core.get_settings().await.unwrap();
    // Simulate an old frontend: the wire format no longer carries the key, so
    // inject it into the deserialized struct the way a compat client would.
    s.google_client_secret = "inline-secret".into();
    core.set_settings(s).await.unwrap();

    assert_eq!(
        credentials::load(0, Slot::GoogleClientSecret).unwrap(),
        "inline-secret"
    );
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());
    assert!(core.get_settings().await.unwrap().has_google_client_secret);
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("inline-secret"));
}
