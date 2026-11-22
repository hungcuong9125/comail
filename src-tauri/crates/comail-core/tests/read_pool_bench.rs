//! Measures read-side contention: the latency of a cheap read (`unread_counts`)
//! while deliberately slow reads occupy the reader side.
//! Gated: COMAIL_TEST_PERF=1 (seeding takes ~10-30s).

use comail_core::db::{Db, repo};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

async fn seed(db: &Db) {
    const MESSAGES: i64 = 60_000;
    const THREADS: i64 = 20_000;
    db.write(move |conn| {
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO accounts (id, email, display_name, provider, auth_kind, username,
                                   imap_host, imap_port, smtp_host, smtp_port, created_at)
             VALUES (1, 'perf@example.com', NULL, 'imap', 'password', 'perf',
                     'localhost', 993, 'localhost', 587, 0)",
            [],
        )?;
        tx.execute(
            "INSERT INTO folders (id, account_id, imap_name, role) VALUES (1, 1, 'INBOX', 'inbox')",
            [],
        )?;
        let words = [
            "meeting", "invoice", "deploy", "quarterly", "flight", "review", "budget",
            "onboarding", "design", "roadmap", "offsite", "launch", "metrics", "hiring",
        ];
        let now: i64 = 1_760_000_000_000;
        {
            let mut ins_thread = tx.prepare(
                "INSERT INTO threads (id, account_id, subject_norm, last_message_at)
                 VALUES (?1, 1, ?2, 0)",
            )?;
            for t in 1..=THREADS {
                ins_thread.execute(rusqlite::params![
                    t,
                    format!(
                        "{} {} update {t}",
                        words[(t as usize * 7) % words.len()],
                        words[(t as usize * 13) % words.len()]
                    )
                ])?;
            }
        }
        {
            let mut ins_msg = tx.prepare(
                "INSERT INTO messages (id, account_id, thread_id, folder_id, uid, message_id,
                     subject, from_name, from_addr, date, is_read, is_automated, snippet, body_state)
                 VALUES (?1, 1, ?2, 1, ?1, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'cached')",
            )?;
            let mut ins_body = tx
                .prepare("INSERT INTO message_bodies (message_id, text_body) VALUES (?1, ?2)")?;
            for m in 1..=MESSAGES {
                let t = (m % THREADS) + 1;
                let w1 = words[(m as usize * 3) % words.len()];
                let w2 = words[(m as usize * 11) % words.len()];
                ins_msg.execute(rusqlite::params![
                    m,
                    t,
                    format!("<perf{m}@example.com>"),
                    format!("{w1} {w2} update {t}"),
                    format!("Sender {}", m % 500),
                    format!("sender{}@example.com", m % 500),
                    now - (MESSAGES - m) * 60_000,
                    (m % 3 != 0) as i64,
                    (m % 5 == 0) as i64,
                    format!("quick note about the {w1} and the {w2}"),
                ])?;
                ins_body.execute(rusqlite::params![
                    m,
                    format!(
                        "Hi team, quick note about the {w1} and the {w2}. \
                         Numbers attached, let me know what you think. ({m})"
                    )
                ])?;
            }
        }
        tx.execute(
            "INSERT INTO messages_fts (rowid, subject, from_text, to_text, body)
             SELECT m.id, m.subject, COALESCE(m.from_name,'') || ' ' || COALESCE(m.from_addr,''),
                    '', COALESCE(b.text_body, '')
             FROM messages m LEFT JOIN message_bodies b ON b.message_id = m.id",
            [],
        )?;
        tx.execute(
            "UPDATE threads SET
                last_message_at = (SELECT MAX(date) FROM messages WHERE thread_id = threads.id),
                message_count   = (SELECT COUNT(*) FROM messages WHERE thread_id = threads.id),
                unread_count    = (SELECT COUNT(*) FROM messages WHERE thread_id = threads.id AND is_read = 0),
                snippet         = (SELECT snippet FROM messages WHERE thread_id = threads.id ORDER BY date DESC LIMIT 1)",
            [],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await
    .unwrap();
    eprintln!("seeded {MESSAGES} messages / {THREADS} threads");
}

/// A real slow read the app issues on every `mail:updated`: the unread-count
/// fan-out. On this corpus it dominates the reader for hundreds of ms.
async fn slow_counts_read(db: &Db) -> Duration {
    let t0 = Instant::now();
    db.read(|conn| repo::counts::unread_counts(conn, Some(1), &[], &[]))
        .await
        .unwrap();
    t0.elapsed()
}

/// A per-keystroke FTS search, the other realistic slow read.
async fn slow_fts_read(db: &Db) -> Duration {
    let t0 = Instant::now();
    db.read(|conn| {
        let q = comail_core::search::parse("meeting OR invoice OR quarterly");
        repo::search::search(conn, &q, 50)
    })
    .await
    .unwrap();
    t0.elapsed()
}

/// A genuinely cheap read: a primary-key thread lookup, the shape of
/// `get_thread` when opening a conversation.
async fn cheap_read(db: &Db) -> Duration {
    let t0 = Instant::now();
    db.read(|conn| repo::threads::get_summary(conn, 12345))
        .await
        .unwrap();
    t0.elapsed()
}

fn report(name: &str, mut samples: Vec<Duration>) {
    samples.sort();
    let min = samples.first().unwrap();
    let med = samples[samples.len() / 2];
    let max = samples.last().unwrap();
    eprintln!(
        "{name}: n={} min={:?} median={:?} max={:?}",
        samples.len(),
        min,
        med,
        max
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cheap_read_latency_behind_slow_reads() {
    if std::env::var("COMAIL_TEST_PERF").as_deref() != Ok("1") {
        eprintln!("skipping (set COMAIL_TEST_PERF=1 to run)");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let db = Db::open(&tmp.path().join("pool.db")).unwrap();
    seed(&db).await;

    // Baseline: how long each query takes alone.
    eprintln!(
        "slow unread_counts alone: {:?}",
        slow_counts_read(&db).await
    );
    eprintln!("slow fts read alone: {:?}", slow_fts_read(&db).await);
    let mut base = Vec::new();
    for _ in 0..10 {
        base.push(cheap_read(&db).await);
    }
    report("cheap read, idle", base);

    // Deterministic contention: one read job sleeping with the reader busy,
    // then a cheap read queued behind it.
    let db2 = db.clone();
    let slow = tokio::spawn(async move {
        db2.read(|conn| {
            std::thread::sleep(Duration::from_millis(800));
            conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?;
            Ok(())
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await; // let the sleep job win the race
    let blocked = cheap_read(&db).await;
    slow.await.unwrap().unwrap();
    eprintln!("cheap read behind 800ms reader blockage: {blocked:?}");

    // Realistic contention: slow reads running continuously while cheap
    // reads arrive (a user opening threads during a sync + counts refetch).
    let stop = Arc::new(AtomicBool::new(false));
    let mut slow_tasks = Vec::new();
    for i in 0..2 {
        let db = db.clone();
        let stop = stop.clone();
        slow_tasks.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                if i == 0 {
                    slow_counts_read(&db).await;
                } else {
                    slow_fts_read(&db).await;
                }
            }
        }));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut contested = Vec::new();
    for _ in 0..20 {
        contested.push(cheap_read(&db).await);
    }
    stop.store(true, Ordering::Relaxed);
    for t in slow_tasks {
        t.await.unwrap();
    }
    report("cheap read, under slow-read load", contested);
}
