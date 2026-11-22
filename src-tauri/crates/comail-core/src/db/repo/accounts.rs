use crate::error::Result;
use crate::models::*;
use rusqlite::{Connection, OptionalExtension, Row, params};

fn account_from_row(row: &Row) -> rusqlite::Result<Account> {
    Ok(Account {
        id: row.get("id")?,
        email: row.get("email")?,
        display_name: row.get("display_name")?,
        provider: Provider::from_str(&row.get::<_, String>("provider")?),
        auth_kind: AuthKind::from_str(&row.get::<_, String>("auth_kind")?),
        sync_state: row.get("sync_state")?,
    })
}

fn config_from_row(row: &Row) -> rusqlite::Result<AccountConfig> {
    Ok(AccountConfig {
        id: row.get("id")?,
        email: row.get("email")?,
        display_name: row.get("display_name")?,
        provider: Provider::from_str(&row.get::<_, String>("provider")?),
        auth_kind: AuthKind::from_str(&row.get::<_, String>("auth_kind")?),
        username: row.get("username")?,
        imap_host: row.get("imap_host")?,
        imap_port: row.get::<_, i64>("imap_port")? as u16,
        smtp_host: row.get("smtp_host")?,
        smtp_port: row.get::<_, i64>("smtp_port")? as u16,
    })
}

/// Durable "removal in flight" marker (migration 039). Written before the
/// first destructive step of `remove_account`; the batched FTS sweep commits
/// per batch, so without a marker a crash or rollback would leave the
/// account's search index silently half-destroyed. While the marker exists
/// the account is hidden from `list` (the UI account list), start-up resumes
/// the removal, and a failed removal repairs the index before clearing it.
pub fn mark_removing(conn: &Connection, id: i64) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO removing_accounts (account_id, marked_at)
         VALUES (?1, ?2)",
        params![id, now_ms()],
    )?;
    Ok(())
}

pub fn unmark_removing(conn: &Connection, id: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM removing_accounts WHERE account_id = ?1",
        params![id],
    )?;
    Ok(())
}

/// Account ids with a removal marker still set - read at start-up to resume
/// interrupted removals before any account task is spawned.
pub fn removal_markers(conn: &Connection) -> Result<Vec<i64>> {
    let mut stmt = conn.prepare("SELECT account_id FROM removing_accounts")?;
    Ok(stmt
        .query_map([], |r| r.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn list(conn: &Connection) -> Result<Vec<Account>> {
    // Accounts mid-removal are not offered as normal accounts: their tasks
    // are stopped and their index may be partway through the sweep.
    let mut stmt = conn.prepare(
        "SELECT * FROM accounts
         WHERE id NOT IN (SELECT account_id FROM removing_accounts)
         ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], account_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn list_configs(conn: &Connection) -> Result<Vec<AccountConfig>> {
    // Accounts marked as removing never get tasks: either the deferred
    // start-up resume is still finishing them, or a failed repair left the
    // marker for the next start.
    let mut stmt = conn.prepare(
        "SELECT * FROM accounts
         WHERE id NOT IN (SELECT account_id FROM removing_accounts)
         ORDER BY id",
    )?;
    let rows = stmt
        .query_map([], config_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_config(conn: &Connection, id: i64) -> Result<Option<AccountConfig>> {
    let mut stmt = conn.prepare("SELECT * FROM accounts WHERE id = ?1")?;
    Ok(stmt.query_row(params![id], config_from_row).optional()?)
}

pub fn get(conn: &Connection, id: i64) -> Result<Option<Account>> {
    let mut stmt = conn.prepare("SELECT * FROM accounts WHERE id = ?1")?;
    Ok(stmt.query_row(params![id], account_from_row).optional()?)
}

pub struct NewAccount<'a> {
    pub email: &'a str,
    pub display_name: Option<&'a str>,
    pub provider: Provider,
    pub auth_kind: AuthKind,
    pub username: &'a str,
    pub imap_host: &'a str,
    pub imap_port: u16,
    pub smtp_host: &'a str,
    pub smtp_port: u16,
}

pub fn insert(conn: &Connection, a: &NewAccount) -> Result<i64> {
    conn.execute(
        "INSERT INTO accounts (email, display_name, provider, auth_kind, username,
                               imap_host, imap_port, smtp_host, smtp_port, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        params![
            a.email,
            a.display_name,
            a.provider.as_str(),
            a.auth_kind.as_str(),
            a.username,
            a.imap_host,
            a.imap_port,
            a.smtp_host,
            a.smtp_port,
            now_ms()
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// FTS rows removed per statement. The mailbox can hold hundreds of
/// thousands of messages; batching keeps each contentless-delete index update
/// (and the rowid subquery materialization) bounded instead of one giant
/// delete inside the single writer's transaction.
pub const FTS_DELETE_BATCH: i64 = 5_000;

/// Delete an account and every auxiliary structure keyed to it that the FK
/// cascade does not reach. Must run inside the caller's transaction: the FTS
/// rows are keyed by message rowid, so they have to go BEFORE the
/// `DELETE FROM accounts` cascades the `messages` rows that identify them.
///
/// Covered explicitly:
/// - `messages_fts`: a virtual FTS5 table with no foreign key; same
///   `DELETE ... rowid` mechanism `repo::messages::delete` uses for one
///   message, batched by account.
/// - `search_events`: `thread_id` is a bare integer with no FK; stale rows
///   would lift a recycled thread id with a dead account's queries.
///
/// Everything else keyed by account/message/thread id (bodies, attachments,
/// labels, snoozes, pending actions, embeddings, calendar/contacts sync
/// state, sync_failures, notification_outbox, ...) is covered by an
/// `ON DELETE CASCADE` back to `accounts` or `messages`.
/// Deletes up to one batch of the account's `messages_fts` rows; returns the
/// number deleted. Callers loop until the result is short of the batch size.
/// Split into per-batch transactions by `remove_account` so the single FIFO
/// writer stays responsive on large accounts.
pub fn sweep_fts_batch(conn: &Connection, id: i64) -> Result<usize> {
    // The LIMIT must bound the FTS rowids, not the message ids: the messages
    // rows are only dropped by the cascade below, so limiting their SELECT
    // would return the same first N ids on every pass and stop early.
    Ok(conn.execute(
        "DELETE FROM messages_fts WHERE rowid IN (
             SELECT rowid FROM messages_fts
             WHERE rowid IN (SELECT id FROM messages WHERE account_id = ?1)
             LIMIT ?2)",
        params![id, FTS_DELETE_BATCH],
    )?)
}

pub fn delete(conn: &Connection, id: i64) -> Result<()> {
    // Re-sweep inside the final transaction: it catches any rows re-indexed
    // between the pre-commit sweep batches and this delete (normally none).
    loop {
        if sweep_fts_batch(conn, id)? < FTS_DELETE_BATCH as usize {
            break;
        }
    }
    conn.execute(
        "DELETE FROM search_events WHERE thread_id IN (
             SELECT id FROM threads WHERE account_id = ?1)",
        params![id],
    )?;
    conn.execute("DELETE FROM accounts WHERE id = ?1", params![id])?;
    Ok(())
}

/// Longest sender name the app accepts; Gmail caps its own "Name" setting
/// at the same length.
pub const DISPLAY_NAME_MAX_CHARS: usize = 60;

/// The name shown in the From: header of mail sent from this account.
pub fn set_display_name(conn: &Connection, id: i64, name: Option<&str>) -> Result<()> {
    conn.execute(
        "UPDATE accounts SET display_name = ?2 WHERE id = ?1",
        params![id, name],
    )?;
    Ok(())
}

pub fn set_sync_state(conn: &Connection, id: i64, state: &str) -> Result<()> {
    conn.execute(
        "UPDATE accounts SET sync_state = ?2 WHERE id = ?1",
        params![id, state],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testutil;

    #[test]
    fn set_display_name_sets_and_clears() {
        let c = testutil::conn();
        testutil::seed_account(&c);
        set_display_name(&c, 1, Some("Ann Lee - Acme Customer Support Team")).unwrap();
        assert_eq!(
            get(&c, 1).unwrap().unwrap().display_name.as_deref(),
            Some("Ann Lee - Acme Customer Support Team")
        );
        set_display_name(&c, 1, None).unwrap();
        assert_eq!(get(&c, 1).unwrap().unwrap().display_name, None);
    }
}
