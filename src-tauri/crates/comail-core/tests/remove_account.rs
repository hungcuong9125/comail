//! Removing an account must leave nothing behind: the contentless FTS index
//! is not covered by the FK cascade, `search_events.thread_id` carries no FK,
//! the in-memory vector index is not part of the database, and the account's
//! background tasks must be stopped before its rows and mail directory go
//! away (a recycled account id must start clean).
//!
//! Real code paths only: `Core::remove_account` against a real `Core`, a real
//! SQLite file, and a real (dead) endpoint for the task-teardown test.

use comail_core::Core;
use comail_core::accounts::credentials::{self, Slot};
use comail_core::config::Paths;
use comail_core::db::Db;
use comail_core::db::repo;
use comail_core::models::*;
use std::time::{Duration, Instant};

const TOKEN_A: &str = "quixoticzebralantern";
const TOKEN_B: &str = "mangrovefalconkettle";

fn insert_account(conn: &rusqlite::Connection, email: &str) -> i64 {
    repo::accounts::insert(
        conn,
        &repo::accounts::NewAccount {
            email,
            display_name: None,
            provider: Provider::Imap,
            auth_kind: AuthKind::Password,
            username: "u",
            imap_host: "127.0.0.1",
            imap_port: 993,
            smtp_host: "127.0.0.1",
            smtp_port: 587,
        },
    )
    .unwrap()
}

/// One incoming message in its own thread; returns (thread_id, message_id).
fn seed_message(conn: &rusqlite::Connection, account_id: i64, subject: &str) -> (i64, i64) {
    conn.execute(
        "INSERT INTO threads (account_id, subject_norm) VALUES (?1, ?2)",
        rusqlite::params![account_id, subject.to_lowercase()],
    )
    .unwrap();
    let thread_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO messages (thread_id, account_id, uid, message_id, subject, from_addr, date)
         VALUES (?1, ?2, ?1, 'mid-' || ?1, ?3, 'x@test.dev', 1000)",
        rusqlite::params![thread_id, account_id, subject],
    )
    .unwrap();
    (thread_id, conn.last_insert_rowid())
}

/// FTS rowids matching a token (the real contentless-delete index, probed
/// directly - no visible_messages join filtering the leak away).
fn fts_matches(conn: &rusqlite::Connection, token: &str) -> Vec<i64> {
    let mut stmt = conn
        .prepare("SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?1")
        .unwrap();
    stmt.query_map(rusqlite::params![token], |r| r.get::<_, i64>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

fn count_where(conn: &rusqlite::Connection, sql: &str, id: i64) -> i64 {
    conn.query_row(sql, rusqlite::params![id], |r| r.get(0))
        .unwrap()
}

/// Removing an account erases its FTS rows, embeddings (persisted and
/// in-memory), search-history rows, staged draft attachments and mail/attach
/// directories - and only its own: the surviving account is untouched.
#[tokio::test]
async fn removal_erases_index_vectors_and_files() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::for_tests(tmp.path());
    paths.ensure().unwrap();
    let core = Core::start(Paths::for_tests(tmp.path())).await.unwrap();

    // Two accounts with one indexed message each, plus a search-history row,
    // persisted embeddings, a live-index vector, and staged files on account 1.
    let paths2 = paths.clone();
    let (t1, m1, t2, m2, draft_id) = core
        .db
        .write(move |conn| {
            let acc1 = insert_account(conn, "a@test.dev");
            let acc2 = insert_account(conn, "b@test.dev");
            assert_eq!((acc1, acc2), (1, 2));
            let (t1, m1) = seed_message(conn, acc1, TOKEN_A);
            let (t2, m2) = seed_message(conn, acc2, TOKEN_B);
            repo::search::index_message(conn, m1).unwrap();
            repo::search::index_message(conn, m2).unwrap();
            repo::embeddings::store_vectors(conn, m1, "m", 3, &[vec![1.0, 0.0, 0.0]]).unwrap();
            repo::embeddings::store_vectors(conn, m2, "m", 3, &[vec![0.0, 1.0, 0.0]]).unwrap();
            for tid in [t1, t2] {
                conn.execute(
                    "INSERT INTO search_events (query, thread_id, sender, opened_at)
                     VALUES ('q', ?1, 's', 0)",
                    rusqlite::params![tid],
                )?;
            }
            // A draft with a staged attachment under the staging root.
            let draft = seed_message(conn, acc1, "draft").1;
            conn.execute("UPDATE messages SET is_draft = 1 WHERE id = ?1", [draft])?;
            let staged_dir = paths2.draft_attachments_dir().join(format!("d{draft}"));
            std::fs::create_dir_all(&staged_dir).unwrap();
            let staged_file = staged_dir.join("att.txt");
            std::fs::write(&staged_file, b"x").unwrap();
            conn.execute(
                "INSERT INTO draft_attachments (draft_id, file_path, filename)
                 VALUES (?1, ?2, 'att.txt')",
                rusqlite::params![draft, staged_file.to_string_lossy()],
            )?;
            Ok((t1, m1, t2, m2, draft))
        })
        .await
        .unwrap();
    let staged_dir = paths.draft_attachments_dir().join(format!("d{draft_id}"));

    // Live in-memory index holds both accounts' vectors.
    let embed = core.embed_state();
    {
        let mut idx = embed.index.write().await;
        idx.reset(3, "m");
        idx.push(m1, 0, &[1.0, 0.0, 0.0]);
        idx.push(m2, 0, &[0.0, 1.0, 0.0]);
    }
    // Mail and attachment caches on disk.
    let mail_dir = paths.mail_dir(1);
    let attach_dir = paths.attachments_dir(1);
    std::fs::create_dir_all(&mail_dir).unwrap();
    std::fs::write(mail_dir.join("1.1.7.eml"), b"raw").unwrap();
    std::fs::create_dir_all(&attach_dir).unwrap();
    std::fs::write(attach_dir.join("a"), b"raw").unwrap();
    assert_eq!(
        core.db
            .read(|conn| Ok(fts_matches(conn, TOKEN_A)))
            .await
            .unwrap(),
        vec![m1],
        "account 1's message is indexed before removal"
    );

    core.remove_account(1).await.unwrap();

    // FTS: no row for the removed account's message, the token matches
    // nothing, the other account's row is untouched.
    let (fts_a, fts_b, emb_a, emb_b, ev_a, ev_b, msgs_a, msgs_b) = core
        .db
        .read(move |conn| {
            Ok((
                fts_matches(conn, TOKEN_A),
                fts_matches(conn, TOKEN_B),
                count_where(
                    conn,
                    "SELECT COUNT(*) FROM message_embeddings WHERE message_id = ?1",
                    m1,
                ),
                count_where(
                    conn,
                    "SELECT COUNT(*) FROM message_embeddings WHERE message_id = ?1",
                    m2,
                ),
                count_where(
                    conn,
                    "SELECT COUNT(*) FROM search_events WHERE thread_id = ?1",
                    t1,
                ),
                count_where(
                    conn,
                    "SELECT COUNT(*) FROM search_events WHERE thread_id = ?1",
                    t2,
                ),
                count_where(
                    conn,
                    "SELECT COUNT(*) FROM messages WHERE account_id = ?1",
                    1,
                ),
                count_where(
                    conn,
                    "SELECT COUNT(*) FROM messages WHERE account_id = ?1",
                    2,
                ),
            ))
        })
        .await
        .unwrap();
    assert!(fts_a.is_empty(), "removed account's FTS rows must be gone");
    assert_eq!(fts_b, vec![m2], "other account's FTS row must survive");
    assert_eq!(
        (emb_a, emb_b),
        (0, 1),
        "embeddings cascade; other account keeps its vectors"
    );
    assert_eq!(
        (ev_a, ev_b),
        (0, 1),
        "search_events has no FK; only account 1's rows go"
    );
    assert_eq!((msgs_a, msgs_b), (0, 1));

    // In-memory index: removed account's vectors gone, other account's remain.
    {
        let idx = embed.index.read().await;
        let hits = idx.search(&[0.0, 1.0, 0.0], 10);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, m2);
        let hits = idx.search(&[1.0, 0.0, 0.0], 10);
        assert!(hits.iter().all(|(mid, _)| *mid != m1));
    }

    // Files: staged draft attachment + its per-file dir, mail dir,
    // attachments dir all gone.
    assert!(!staged_dir.exists());
    assert!(!mail_dir.exists());
    assert!(!attach_dir.exists());
}

/// SQLite reuses an INTEGER PRIMARY KEY after the max row is deleted. The
/// re-added account with the same id must start with no stale index rows,
/// vectors, or search history attributed to it.
#[tokio::test]
async fn readded_account_with_recycled_id_starts_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::for_tests(tmp.path());
    paths.ensure().unwrap();
    let core = Core::start(Paths::for_tests(tmp.path())).await.unwrap();

    let (t1, m1) = core
        .db
        .write(|conn| {
            insert_account(conn, "a@test.dev");
            let (t1, m1) = seed_message(conn, 1, TOKEN_A);
            repo::search::index_message(conn, m1).unwrap();
            repo::embeddings::store_vectors(conn, m1, "m", 3, &[vec![1.0, 0.0, 0.0]]).unwrap();
            conn.execute(
                "INSERT INTO search_events (query, thread_id, sender, opened_at)
                 VALUES ('q', ?1, 's', 0)",
                rusqlite::params![t1],
            )?;
            Ok((t1, m1))
        })
        .await
        .unwrap();
    {
        let embed = core.embed_state();
        let mut idx = embed.index.write().await;
        idx.reset(3, "m");
        idx.push(m1, 0, &[1.0, 0.0, 0.0]);
    }

    core.remove_account(1).await.unwrap();

    // Re-add: id 1 was the max, so SQLite recycles it.
    let new_id = core
        .db
        .write(|conn| Ok(insert_account(conn, "a@test.dev")))
        .await
        .unwrap();
    assert_eq!(new_id, 1, "expected the account id to be recycled");

    let (fts_left, emb_left, ev_left) = core
        .db
        .read(move |conn| {
            Ok((
                fts_matches(conn, TOKEN_A),
                conn.query_row("SELECT COUNT(*) FROM message_embeddings", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
                count_where(
                    conn,
                    "SELECT COUNT(*) FROM search_events WHERE thread_id = ?1",
                    t1,
                ),
            ))
        })
        .await
        .unwrap();
    let idx_empty = core.embed_state().index.read().await.is_empty();
    assert!(fts_left.is_empty());
    assert_eq!(emb_left, 0);
    assert_eq!(ev_left, 0);
    assert!(idx_empty);
}

/// A task parked in a network call (here: TLS greeting from a server that
/// accepts and never speaks) must not hold removal hostage: the shared stop
/// flag is signaled, the bounded wait expires, the straggler is aborted, and
/// no mail directory reappears afterwards.
#[test]
fn removal_aborts_tasks_parked_on_a_dead_server() {
    let creds =
        std::env::temp_dir().join(format!("comail-remove-creds-{}.json", std::process::id()));
    // Mutating process env is only safe before the runtime exists and its
    // worker threads can read it - hence a manual runtime inside a plain
    // test instead of #[tokio::test(flavor = "multi_thread")].
    unsafe { std::env::set_var("COMAIL_CREDENTIALS_INSECURE_FILE", &creds) };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_dead_server_removal(creds));
}

async fn run_dead_server_removal(creds: std::path::PathBuf) {
    // Accept every connection and hold it open without a word: the client's
    // TLS handshake parks waiting for the greeting, and only the stop timeout
    // + abort can free the task.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
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
                    display_name: None,
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
    credentials::store_async(account_id, Slot::Password, "pass".into())
        .await
        .unwrap();
    drop(db);

    let core = Core::start(Paths::for_tests(tmp.path())).await.unwrap();
    core.notify_ui_ready();

    // Wait until the task set is spawned (actors start after ui_ready).
    let started = Instant::now();
    let handle = loop {
        if let Some(h) = core.debug_handle(account_id).await {
            break h;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "actor never spawned"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    let started = Instant::now();
    core.remove_account(account_id).await.unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(30),
        "remove_account hung against a dead endpoint: {elapsed:?}"
    );

    // Every tracked task - joined or aborted - reports finished.
    assert!(
        handle.tasks_finished(),
        "task set still running after removal"
    );
    assert!(core.debug_handle(account_id).await.is_none());

    // Give any hypothetical straggler a moment, then check nothing recreated
    // the mail directory.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!paths.mail_dir(account_id).exists());
    assert!(!paths.attachments_dir(account_id).exists());

    let _ = std::fs::remove_file(&creds);
}
