//! Sync Now on an account whose IMAP connection cannot be established must
//! surface the real cause promptly - not hang until the client's 45 s
//! timeout, and not report "sync actor stopped" because the waiter was
//! dropped in a retry wait.
//!
//! No live server needed: a listener that accepts and immediately drops the
//! connection kills the TLS handshake just like a refused port (without the
//! bind-then-drop reuse race), and an account with no stored credential
//! exercises the auth-failure arm. One test covers both arms back to back
//! (the actor reloads credentials on every connect attempt), keeping the
//! process-global credentials-file env var free of cross-test races.

use comail_core::Core;
use comail_core::accounts::credentials::{self, Slot};
use comail_core::config::Paths;
use comail_core::db::Db;
use comail_core::db::repo;
use comail_core::error::CoreError;
use comail_core::models::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// `sync_now` errors with NotFound until the account's actor has spawned
/// (actors start asynchronously after notify_ui_ready); retry through that
/// window, then return the actor's real answer.
async fn sync_now_when_up(core: &Core, account_id: i64) -> Result<(), CoreError> {
    let started = Instant::now();
    loop {
        match core.sync_now(Some(account_id)).await {
            Err(CoreError::NotFound(_)) => {
                assert!(
                    started.elapsed() < Duration::from_secs(20),
                    "actor never spawned"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            result => return result,
        }
    }
}

async fn run(creds: PathBuf) {
    // Accept every connection and drop it at once: the TLS handshake dies
    // immediately, exercising the same connect-failure arm as a refused
    // port while keeping the port bound for the whole test.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });

    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::for_tests(tmp.path());
    paths.ensure().unwrap();
    let db = Db::open(&paths.db_file()).unwrap();
    let account_id = db
        .write(move |conn| {
            repo::accounts::insert(
                conn,
                &repo::accounts::NewAccount {
                    email: "gone@example.com",
                    display_name: Some("Gone"),
                    provider: Provider::Imap,
                    auth_kind: AuthKind::Password,
                    username: "gone",
                    imap_host: "127.0.0.1",
                    imap_port: port,
                    smtp_host: "127.0.0.1",
                    smtp_port: port,
                },
            )
        })
        .await
        .expect("seed account");

    let core = Core::start(Paths::for_tests(tmp.path())).await.unwrap();
    core.notify_ui_ready();

    // Arm 1: no stored credential, connect() fails at auth. The Sync Now
    // nudge is answered with the auth cause, not a 45 s timeout.
    let started = Instant::now();
    let err = sync_now_when_up(&core, account_id).await.unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "Sync Now hung instead of reporting the auth failure: {err}"
    );
    assert!(
        err.to_string().contains("authentication required"),
        "expected the auth cause, got: {err}"
    );

    // Arm 2: with a credential stored the same Sync Now nudge retries the
    // connect, which the accept-then-drop listener kills - the waiter gets
    // that error.
    credentials::store_async(account_id, Slot::Password, "pass".into())
        .await
        .unwrap();
    let started = Instant::now();
    let err = sync_now_when_up(&core, account_id).await.unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "Sync Now hung instead of reporting the connect failure: {err}"
    );
    let msg = err.to_string();
    assert!(
        !msg.contains("timed out") && !msg.contains("sync actor stopped"),
        "expected the real cause, got: {msg}"
    );

    let _ = std::fs::remove_file(&creds);
}

#[test]
fn sync_now_reports_the_real_cause_immediately() {
    let creds =
        std::env::temp_dir().join(format!("comail-syncnow-creds-{}.json", std::process::id()));
    // Mutating process env is only safe before the runtime exists and its
    // worker threads can read it - hence a manual runtime inside a plain
    // test instead of #[tokio::test(flavor = "multi_thread")].
    unsafe { std::env::set_var("COMAIL_CREDENTIALS_INSECURE_FILE", &creds) };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(creds));
}
