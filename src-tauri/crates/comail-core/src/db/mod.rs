//! SQLite access. WAL mode: one dedicated writer thread + a small fixed pool
//! of reader threads, each owning a Connection. Async callers submit closures
//! and await results, so all repo code is plain synchronous rusqlite.

pub mod migrations;
pub mod repo;

use crate::error::{CoreError, Result};
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use tokio::sync::oneshot;

type Job = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

/// Readers run jobs concurrently so a slow query (full-text search, the
/// unread-count fan-out) cannot head-of-line block cheap reads behind it.
/// WAL gives each connection an independent read snapshot. 4 covers a
/// counts refetch, a search, and a view load in flight at once.
const READ_POOL_SIZE: usize = 4;

#[derive(Clone)]
pub struct Db {
    write_tx: mpsc::Sender<Job>,
    read_tx: mpsc::Sender<Job>,
}

fn spawn_conn_thread(path: std::path::PathBuf, name: &str) -> Result<mpsc::Sender<Job>> {
    let (tx, rx) = mpsc::channel::<Job>();
    let mut conn = open_connection(&path)?;
    std::thread::Builder::new()
        .name(format!("comail-db-{name}"))
        .spawn(move || {
            while let Ok(job) = rx.recv() {
                run_job(&mut conn, job);
            }
        })
        .map_err(CoreError::Io)?;
    Ok(tx)
}

/// A pool of reader threads sharing one job queue. `std::sync::mpsc` has no
/// multi-consumer channel, so the receivers contend on the lock: whichever
/// thread holds it takes the next job, and the others take what follows.
/// A thread busy inside `run_job` never holds the lock, so slow jobs leave
/// the queue open to the remaining readers. Like the writer, each thread
/// exits once the senders are gone and the queue is drained.
fn spawn_read_pool(path: &Path, size: usize) -> Result<mpsc::Sender<Job>> {
    let (tx, rx) = mpsc::channel::<Job>();
    let rx = Arc::new(Mutex::new(rx));
    for i in 0..size {
        let mut conn = open_connection(path)?;
        let rx = Arc::clone(&rx);
        std::thread::Builder::new()
            .name(format!("comail-db-reader-{i}"))
            .spawn(move || {
                loop {
                    let job = {
                        // Poison means a holder panicked while waiting on the
                        // channel; recovering keeps the remaining readers alive.
                        let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
                        match guard.recv() {
                            Ok(job) => job,
                            Err(_) => return,
                        }
                    };
                    run_job(&mut conn, job);
                }
            })
            .map_err(CoreError::Io)?;
    }
    Ok(tx)
}

/// Run one job, keeping the connection thread alive if it panics. A dead
/// writer thread would fail every later write until relaunch. The panicking
/// job's reply sender is dropped while unwinding, so its caller gets an error.
fn run_job(conn: &mut Connection, job: Job) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(conn))).is_err() {
        // Unwinding dropped any rusqlite Transaction (which rolls back); a raw
        // BEGIN would still be open, so close it here.
        if !conn.is_autocommit() {
            let _ = conn.execute_batch("ROLLBACK");
        }
        // Fixed text: the panic payload may quote message content.
        tracing::error!("database job panicked; rolled back and continuing");
    }
}

fn open_connection(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    // Read-latency tuning: mmap the db file (256 MB window) so page reads
    // skip the syscall path, keep a 64 MB page cache, and spill temp
    // b-trees (sorts, group-bys) to memory instead of disk.
    conn.pragma_update(None, "mmap_size", 268_435_456i64)?;
    conn.pragma_update(None, "cache_size", -65_536i64)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(conn)
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Run migrations on a throwaway connection before the threads start.
        {
            let mut conn = open_connection(path)?;
            migrations::run(&mut conn)?;
            repo::contacts::backfill_folded(&conn)?;
        }
        let write_tx = spawn_conn_thread(path.to_path_buf(), "writer")?;
        let read_tx = spawn_read_pool(path, READ_POOL_SIZE)?;
        Ok(Db { write_tx, read_tx })
    }

    async fn call<T, F>(&self, tx: &mpsc::Sender<Job>, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(Box::new(move |conn| {
            let _ = reply_tx.send(f(conn));
        }))
        .map_err(|_| CoreError::Other("db thread gone".into()))?;
        // Fails when the job panicked (see `run_job`) before replying.
        reply_rx
            .await
            .map_err(|_| CoreError::Other("db call dropped".into()))?
    }

    /// Run a write (or transactional) closure on the writer connection.
    pub async fn write<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        self.call(&self.write_tx, f).await
    }

    /// Run a read-only closure on one of the pooled reader connections.
    pub async fn read<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        self.call(&self.read_tx, f).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn panicking_job_errors_and_writer_keeps_running() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        db.write(|c| Ok(c.execute_batch("CREATE TABLE t (v INTEGER)")?))
            .await
            .unwrap();

        // Panic mid-transaction, both with a rusqlite Transaction and a raw
        // BEGIN: the caller sees an error and nothing is committed.
        let res = db
            .write(|c| -> Result<()> {
                let tx = c.transaction()?;
                tx.execute("INSERT INTO t VALUES (1)", [])?;
                panic!("boom");
            })
            .await;
        assert!(res.is_err());
        let res = db
            .write(|c| -> Result<()> {
                c.execute_batch("BEGIN; INSERT INTO t VALUES (2);")?;
                panic!("boom");
            })
            .await;
        assert!(res.is_err());

        // The writer thread survived and the connection is usable again.
        let (autocommit, count) = db
            .write(|c| {
                let autocommit = c.is_autocommit();
                c.execute("INSERT INTO t VALUES (3)", [])?;
                let n: i64 = c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;
                Ok((autocommit, n))
            })
            .await
            .unwrap();
        assert!(autocommit);
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn a_slow_read_does_not_block_other_reads() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        db.write(|c| Ok(c.execute_batch("CREATE TABLE t (v INTEGER)")?))
            .await
            .unwrap();

        // Occupy all but one reader with a sleeping job; a cheap read would
        // wait ~500ms on a single reader, but the pool has one free worker.
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut slow = Vec::new();
        for _ in 0..READ_POOL_SIZE - 1 {
            let db = db.clone();
            let started = started.clone();
            slow.push(tokio::spawn(async move {
                db.read(move |conn| {
                    started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?;
                    Ok(())
                })
                .await
            }));
        }
        // Wait until the sleep jobs actually hold readers before timing.
        while started.load(std::sync::atomic::Ordering::SeqCst) < READ_POOL_SIZE - 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let start = std::time::Instant::now();
        db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap();
        assert!(
            start.elapsed() < std::time::Duration::from_millis(400),
            "cheap read waited {:?} behind slow reads",
            start.elapsed()
        );
        for s in slow {
            s.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn panicking_read_job_errors_and_the_pool_keeps_running() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        // Saturate the pool with panicking jobs; every caller sees an error.
        let mut panics = Vec::new();
        for _ in 0..READ_POOL_SIZE * 2 {
            let db = db.clone();
            panics.push(tokio::spawn(async move {
                db.read(|_| -> Result<()> { panic!("boom") }).await
            }));
        }
        for p in panics {
            assert!(p.await.unwrap().is_err());
        }
        // Every reader thread survived: submit one job per pool member and
        // check they all run concurrently (sleeping jobs overlap).
        let start = std::time::Instant::now();
        let mut jobs = Vec::new();
        for _ in 0..READ_POOL_SIZE {
            let db = db.clone();
            jobs.push(tokio::spawn(async move {
                db.read(|conn| {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?;
                    Ok(())
                })
                .await
            }));
        }
        for j in jobs {
            j.await.unwrap().unwrap();
        }
        assert!(
            start.elapsed() < std::time::Duration::from_millis(400),
            "pool did not run reads in parallel ({:?})",
            start.elapsed()
        );
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use rusqlite::{Connection, params};

    /// In-memory DB with all migrations applied.
    pub fn conn() -> Connection {
        let mut c = Connection::open_in_memory().unwrap();
        super::migrations::run(&mut c).unwrap();
        c
    }

    /// Account 1 with an inbox folder 1, the minimum most repos need.
    pub fn seed_account(c: &Connection) {
        c.execute(
            "INSERT INTO accounts (id, email, provider, auth_kind, username,
             imap_host, imap_port, smtp_host, smtp_port, created_at)
             VALUES (1,'me@test.dev','imap','password','me','h',993,'h',587,0)",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO folders (id, account_id, imap_name, role) VALUES (1,1,'INBOX','inbox')",
            [],
        )
        .unwrap();
    }

    /// One incoming message in its own thread; returns (thread_id, message_id).
    pub fn seed_message(
        c: &Connection,
        from_addr: &str,
        subject: &str,
        is_automated: bool,
    ) -> (i64, i64) {
        c.execute(
            "INSERT INTO threads (account_id, subject_norm, unread_count, last_message_at)
             VALUES (1, ?1, 1, 1000)",
            params![subject.to_lowercase()],
        )
        .unwrap();
        let thread_id = c.last_insert_rowid();
        c.execute(
            "INSERT INTO messages (thread_id, account_id, folder_id, uid, message_id, subject,
             from_addr, date, is_read, is_automated, is_draft, is_outgoing)
             VALUES (?1, 1, 1, ?1, 'mid-' || ?1, ?2, ?3, 1000, 0, ?4, 0, 0)",
            params![thread_id, subject, from_addr, is_automated as i64],
        )
        .unwrap();
        let msg_id = c.last_insert_rowid();
        (thread_id, msg_id)
    }

    /// `n` messages under one thread plus their FTS rows, in two statements -
    /// bulk seed for sweep/repair tests that need thousands of indexed rows.
    pub fn seed_bulk_messages(c: &Connection, account_id: i64, n: i64, body_token: &str) {
        c.execute(
            "INSERT INTO threads (account_id, subject_norm) VALUES (?1, 'bulk')",
            params![account_id],
        )
        .unwrap();
        let tid = c.last_insert_rowid();
        c.execute(
            "WITH RECURSIVE seq(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM seq WHERE i < ?1)
             INSERT INTO messages (thread_id, account_id, folder_id, uid, message_id,
                                   subject, from_addr, date, is_read, is_automated,
                                   is_draft, is_outgoing)
             SELECT ?2, ?3, 1, 100000000 + i, 'mid-' || i, 'subject ' || i, 'a@b.c',
                    1000, 0, 0, 0, 0
             FROM seq",
            params![n, tid, account_id],
        )
        .unwrap();
        c.execute(
            "INSERT INTO messages_fts (rowid, subject, from_text, to_text, body)
             SELECT id, subject, 'a@b.c', 'x', ?2 FROM messages WHERE account_id = ?1",
            params![account_id, body_token],
        )
        .unwrap();
    }
}
