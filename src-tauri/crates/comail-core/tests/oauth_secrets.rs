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
use comail_core::error::CoreError;
use comail_core::models::{Provider, Settings};
use comail_core::oauth::providers::{
    self, SecretState, reset_provider_config, resolve_credentials, set_configured, set_probe_gate,
    set_reprobe_interval,
};
use std::path::Path;
use std::time::Duration;

static CREDS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Point the insecure-file credential backend at `path` and hold the guard
/// serializing every credential-touching test. The process-global resolver
/// cache is reset so tests cannot see each other's state, and the re-probe
/// interval starts effectively infinite — tests that exercise recovery
/// shrink it explicitly.
async fn creds_env(path: &Path) -> tokio::sync::MutexGuard<'static, ()> {
    let guard = CREDS_LOCK.lock().await;
    reset_provider_config();
    set_reprobe_interval(Duration::from_secs(86_400));
    // SAFETY: the guard serializes every use of the shared backend file.
    unsafe { std::env::set_var("COMAIL_CREDENTIALS_INSECURE_FILE", path) };
    guard
}

/// The pre-keyring settings row: both client secrets inline. Written as raw
/// JSON — `repo::settings::set` deliberately never stores an inline secret
/// from an incoming object, so this reproduces exactly what an old build
/// left behind.
async fn seed_legacy_settings(db: &Db) {
    db.write(|conn| {
        let mut s = repo::settings::get(conn)?;
        s.google_client_id = "g-id".into();
        s.ms_client_id = "ms-id".into();
        let mut json = serde_json::to_value(&s).unwrap();
        json["googleClientSecret"] = "g-secret".into();
        json["msClientSecret"] = "ms-secret".into();
        conn.execute(
            "INSERT INTO app_settings (key, value) VALUES ('settings', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [&serde_json::to_string(&json).unwrap()],
        )?;
        Ok(())
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
/// still works through the resolver's fallback — including AFTER a
/// whole-object settings write, which must re-derive the fallback from the
/// stored row. A later retry with a working keyring migrates.
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

        // A whole-object write while the keyring is down (the frontend sends
        // no secret fields at all): the row copy must survive — and the
        // resolver must still serve it after the write, not just before.
        let mut s: Settings = core.get_settings().await.unwrap();
        s.theme = "carbon".into();
        core.set_settings(s).await.unwrap();
        let json = row_json(&db).await;
        assert_eq!(json["googleClientSecret"], "g-secret");
        assert_eq!(json["msClientSecret"], "ms-secret");
        let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
        assert_eq!(secret.as_deref(), Some("g-secret"));
        let (_, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
        assert_eq!(secret.as_deref(), Some("ms-secret"));
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

/// A stale inline secret in a settings write is ignored entirely: it is
/// never stored (only the migration moves row → keyring) and never applied,
/// so a compat client cannot clobber a newer keyring value.
#[tokio::test(flavor = "multi_thread")]
async fn set_settings_ignores_inline_secret_fields() {
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
    core.set_oauth_client_secret("google".into(), "live-secret".into())
        .await
        .unwrap();

    let mut s = core.get_settings().await.unwrap();
    // Simulate a stale frontend sending the retired field inline.
    s.google_client_secret = "stale-inline".into();
    core.set_settings(s).await.unwrap();

    // Not in the keyring, not in the row, not served by the resolver.
    assert_eq!(
        credentials::load(0, Slot::GoogleClientSecret).unwrap(),
        "live-secret"
    );
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("live-secret"));
    assert!(core.get_settings().await.unwrap().has_google_client_secret);
}

/// When the keyring already holds a value that differs from the row's, the
/// keyring wins — it was written by set_oauth_client_secret or an earlier
/// migration, so it is the newer value by construction. The stale row copy
/// is still stripped. This also closes the store-ok/strip-failed race: a row
/// secret left behind cannot resurrect over a newer keyring value.
#[tokio::test(flavor = "multi_thread")]
async fn migration_keyring_wins_over_stale_row_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let _guard = creds_env(&tmp.path().join("credentials.json")).await;
    let db = Db::open(&paths(&tmp).db_file()).unwrap();
    seed_legacy_settings(&db).await;
    // Newer value already in the keyring (e.g. set after a failed strip).
    credentials::store(0, Slot::GoogleClientSecret, "newer-secret").unwrap();

    let core = Core::start(paths(&tmp)).await.unwrap();

    // The keyring value is untouched; the stale row copy is dropped.
    assert_eq!(
        credentials::load(0, Slot::GoogleClientSecret).unwrap(),
        "newer-secret"
    );
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("newer-secret"));
    // Microsoft migrated normally.
    assert_eq!(
        credentials::load(0, Slot::MsClientSecret).unwrap(),
        "ms-secret"
    );
    let _ = core;
}

/// Clearing an app-level secret deletes exactly its slot. Clearing the AI
/// key must leave the OAuth client secrets, the MCP token and the decision
/// keys intact (a prefix delete on account 0 in the file backend wiped them
/// all); clearing one OAuth secret leaves the other; and deleting a mailbox
/// account's credentials never touches app-level secrets.
#[tokio::test(flavor = "multi_thread")]
async fn clearing_app_secrets_is_exact() {
    let tmp = tempfile::tempdir().unwrap();
    let _guard = creds_env(&tmp.path().join("credentials.json")).await;
    let core = Core::start(paths(&tmp)).await.unwrap();

    credentials::store(0, Slot::AiApiKey, "ai-key").unwrap();
    credentials::store(0, Slot::McpToken, "mcp").unwrap();
    credentials::store(0, Slot::DecisionApiKey, "decision").unwrap();
    credentials::store(0, Slot::GoogleClientSecret, "g-secret").unwrap();
    credentials::store(0, Slot::MsClientSecret, "ms-secret").unwrap();
    credentials::store(1, Slot::RefreshToken, "acct-refresh").unwrap();
    credentials::store(1, Slot::Password, "acct-pass").unwrap();

    // Clearing the AI key removes only that slot.
    core.set_ai_key(String::new()).await.unwrap();
    assert!(credentials::load(0, Slot::AiApiKey).is_err());
    for slot in [
        Slot::McpToken,
        Slot::DecisionApiKey,
        Slot::GoogleClientSecret,
        Slot::MsClientSecret,
    ] {
        assert!(credentials::load(0, slot).is_ok(), "app-level secret wiped");
    }

    // Clearing one OAuth secret leaves the other.
    core.set_oauth_client_secret("google".into(), String::new())
        .await
        .unwrap();
    assert!(credentials::load(0, Slot::GoogleClientSecret).is_err());
    assert_eq!(
        credentials::load(0, Slot::MsClientSecret).unwrap(),
        "ms-secret"
    );

    // Removing a mailbox account deletes its slots and nothing app-level.
    credentials::delete_all(1);
    assert!(credentials::load(1, Slot::RefreshToken).is_err());
    assert!(credentials::load(1, Slot::Password).is_err());
    for slot in [Slot::McpToken, Slot::DecisionApiKey, Slot::MsClientSecret] {
        assert!(credentials::load(0, slot).is_ok(), "app-level secret wiped");
    }
}

/// A real keyring error is a transient store problem, never "no secret":
/// with no legacy copy the resolver fails as a Keyring error (sync never
/// maps it to needs_reauth), and a failed clear is surfaced to the caller.
#[tokio::test(flavor = "multi_thread")]
async fn keyring_errors_are_transient_and_surfaced() {
    let tmp = tempfile::tempdir().unwrap();
    let broken = tmp.path().join("creds-is-a-dir");
    std::fs::create_dir(&broken).unwrap();
    let _guard = creds_env(&broken).await;
    let core = Core::start(paths(&tmp)).await.unwrap();

    // Resolver-level: Unavailable with no legacy must not resolve to "no
    // secret" — a token request without client_secret would return an auth
    // error and flag the account needs_reauth.
    set_configured(Provider::Gmail, "g-id", None, SecretState::Unavailable);
    match resolve_credentials(Provider::Gmail).await {
        Err(CoreError::Keyring(_)) => {}
        other => panic!("expected transient keyring error, got {other:?}"),
    }

    // A failed clear is surfaced — the file backend is a directory, so the
    // delete's write-back fails and the command must not report success.
    set_configured(
        Provider::Gmail,
        "g-id",
        None,
        SecretState::Value("s".into()),
    );
    let err = core
        .set_oauth_client_secret("google".into(), String::new())
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Io(_)) || matches!(err, CoreError::Other(_)));
}

/// `Unavailable` is not sticky: once the credential store works again the
/// resolver re-probes (rate-limited, single-flight) and recovers without a
/// restart or a settings write — completing a pending migration when the
/// keyring reads back empty but a row copy is cached.
#[tokio::test(flavor = "multi_thread")]
async fn unavailable_state_heals_via_reprobe() {
    let tmp = tempfile::tempdir().unwrap();
    let broken = tmp.path().join("creds-is-a-dir");
    std::fs::create_dir(&broken).unwrap();
    let good = tmp.path().join("credentials.json");
    let db = Db::open(&paths(&tmp).db_file()).unwrap();
    seed_legacy_settings(&db).await;

    // Start with an unusable store: migration fails, both providers sit in
    // Unavailable with their legacy row copies as the working fallback.
    let _guard = creds_env(&broken).await;
    let core = Core::start(paths(&tmp)).await.unwrap();
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("g-secret"));

    // The store works again — but inside the rate-limit window no re-probe
    // runs: the keyring still holds nothing.
    unsafe { std::env::set_var("COMAIL_CREDENTIALS_INSECURE_FILE", &good) };
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("g-secret"));
    assert!(credentials::load(0, Slot::GoogleClientSecret).is_err());

    // Past the interval the resolver re-probes: the keyring reads empty, the
    // cached row copy completes the pending migration, and the value is
    // served from the store — no restart, no set_settings.
    set_reprobe_interval(Duration::ZERO);
    let (_, secret) = resolve_credentials(Provider::Gmail).await.unwrap();
    assert_eq!(secret.as_deref(), Some("g-secret"));
    assert_eq!(
        credentials::load(0, Slot::GoogleClientSecret).unwrap(),
        "g-secret"
    );
    // The pending row key is cleaned up by the next routine migration pass.
    core.migrate_oauth_client_secrets().await;
    let json = row_json(&db).await;
    assert!(json.get("googleClientSecret").is_none());

    // Unavailable with no legacy at all also heals: seed the state by hand
    // (a read-side keyring error can't be produced by the file backend —
    // missing and unreadable entries both read as empty), then let the real
    // re-probe find the recovered value.
    set_configured(Provider::Microsoft, "ms-id", None, SecretState::Unavailable);
    credentials::store(0, Slot::MsClientSecret, "recovered").unwrap();
    let (_, secret) = resolve_credentials(Provider::Microsoft).await.unwrap();
    assert_eq!(secret.as_deref(), Some("recovered"));
}

/// A probe result computed before an explicit write must never overwrite
/// it — in the cache or the keyring. The gate parks the re-probe between
/// its keyring read (result: Unset) and its commit while the user saves a
/// new secret; releasing it must not resurrect the stale outcome.
#[tokio::test(flavor = "multi_thread")]
async fn stale_probe_result_cannot_overwrite_a_newer_write() {
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
    set_configured(
        Provider::Gmail,
        "g-id",
        Some("row-secret"),
        SecretState::Unavailable,
    );
    set_reprobe_interval(Duration::ZERO);
    let gate = std::sync::Arc::new(providers::ProbeGate {
        parked: tokio::sync::Barrier::new(2),
        release: tokio::sync::Barrier::new(2),
    });
    set_probe_gate(Some(gate.clone()));

    // resolve → re-probe → reads the empty keyring (Unset) → parks.
    let resolve = tokio::spawn(async { resolve_credentials(Provider::Gmail).await });
    gate.parked.wait().await;
    set_probe_gate(None);

    // The explicit write lands while the probe result is stale — only then
    // is the parked probe allowed to attempt its commit.
    core.set_oauth_client_secret("google".into(), "new-secret".into())
        .await
        .unwrap();
    gate.release.wait().await;

    // The commit is dropped: resolver and keyring both hold the new secret —
    // never the stale Unset or the pending row copy.
    let (id, secret) = resolve.await.unwrap().unwrap();
    assert_eq!(id, "g-id");
    assert_eq!(secret.as_deref(), Some("new-secret"));
    assert_eq!(
        credentials::load(0, Slot::GoogleClientSecret).unwrap(),
        "new-secret"
    );
}

/// Cold start with a keyring secret but no client ID: the presence probe
/// runs even without an entry, so the flag — and the Clear button — survive
/// a restart. (Proves the cold case: the provider cache was reset first.)
#[tokio::test(flavor = "multi_thread")]
async fn cold_start_reports_secret_without_client_id() {
    let tmp = tempfile::tempdir().unwrap();
    let _guard = creds_env(&tmp.path().join("credentials.json")).await;
    reset_provider_config();
    credentials::store(0, Slot::GoogleClientSecret, "stored-secret").unwrap();

    let core = Core::start(paths(&tmp)).await.unwrap();
    let settings = core.get_settings().await.unwrap();
    assert!(settings.has_google_client_secret);
    assert!(!settings.has_ms_client_secret);
}
