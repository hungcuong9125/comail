//! Wakes snoozed threads and nudges account actors when timed actions
//! (send-later, undo-send windows) come due. Timers are app-local: anything
//! past due fires on the next tick or at launch.

use crate::db::Db;
use crate::db::repo;
use crate::events::{CoreEvent, EventBus};
use crate::models::now_ms;
use futures::FutureExt;
use rusqlite::OptionalExtension;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::caldav::task::CalTaskHandle;
use crate::sync::engine::{AccountHandle, SyncCmd};

const TICK_SECS: u64 = 5;

pub fn spawn(
    db: Db,
    bus: EventBus,
    handles: Arc<RwLock<HashMap<i64, AccountHandle>>>,
    cal_handles: Arc<RwLock<HashMap<i64, CalTaskHandle>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut nudged_until: i64 = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(TICK_SECS)).await;
            // A panic in one tick (e.g. on hostile calendar data) must not end
            // the loop: snooze wake-ups, send-later and reminders all ride on it.
            let ticked =
                AssertUnwindSafe(tick(&db, &bus, &handles, &cal_handles, &mut nudged_until))
                    .catch_unwind()
                    .await;
            if ticked.is_err() {
                // Fixed text: the panic payload may quote message content.
                tracing::error!("scheduler tick panicked; continuing");
            }
        }
    })
}

async fn tick(
    db: &Db,
    bus: &EventBus,
    handles: &RwLock<HashMap<i64, AccountHandle>>,
    cal_handles: &RwLock<HashMap<i64, CalTaskHandle>>,
    nudged_until: &mut i64,
) {
    let now = now_ms();

    // 1. Wake snoozed threads.
    let woken = db.read(move |conn| repo::snoozes::woken(conn, now)).await;
    if let Ok(woken) = woken {
        let mut nudged_accounts: Vec<i64> = Vec::new();
        for thread_id in woken {
            let res = db.write(move |conn| wake_thread(conn, thread_id)).await;
            if let Ok(account_id) = res {
                bus.emit(CoreEvent::ThreadWoke { thread_id });
                if let Some(account_id) = account_id
                    && !nudged_accounts.contains(&account_id)
                {
                    nudged_accounts.push(account_id);
                }
            }
        }
        // A woken thread that was read enqueues a mark_unread action; nudge
        // its account's mutation worker like perform_action does.
        for account_id in nudged_accounts {
            if let Some(handle) = handles.read().await.get(&account_id) {
                handle.send(SyncCmd::RunActions);
            }
        }
    }

    // 2. Nudge actors when a timed pending action becomes due.
    if let Ok(Some(due_at)) = db.read(|conn| repo::actions::next_due_at(conn)).await {
        if due_at <= now && due_at > *nudged_until - 60_000 {
            *nudged_until = now;
            for handle in handles.read().await.values() {
                handle.send(SyncCmd::RunActions);
            }
            for handle in cal_handles.read().await.values() {
                handle.nudge();
            }
        }
    }

    // 3. Meeting reminders: fire once per occurrence inside the lead
    // window. Recurring events are covered because list_events
    // expansion is not needed here - the notified_at gate compares
    // against each occurrence start via upcoming_for_notify + the
    // expander below for recurring masters.
    let lead_min = db
        .read(|conn| Ok(repo::settings::get(conn)?.meeting_notify_lead_minutes))
        .await
        .unwrap_or(0);
    if lead_min > 0 {
        let lead_ms = lead_min * 60_000;
        if let Ok(due) = db
            .read(move |conn| repo::calendar::upcoming_for_notify(conn, now, lead_ms))
            .await
        {
            for ev in due {
                let event_id = ev.id;
                let occurrence_start = ev.starts_at;
                let _ = db
                    .write(move |conn| {
                        repo::calendar::set_notified(conn, event_id, occurrence_start)
                    })
                    .await;
                bus.emit(CoreEvent::EventReminder {
                    event: ev,
                    occurrence_start,
                });
            }
        }
        // Recurring masters: check the next occurrence explicitly.
        if let Ok(masters) = db
            .read(move |conn| repo::calendar::recurring_masters(conn, now + lead_ms))
            .await
        {
            for m in masters {
                // Same gates as upcoming_for_notify: cancelled series
                // (incl. CANCEL tombstones) and declined invites are
                // silent.
                if m.event.status.as_deref() == Some("CANCELLED")
                    || m.event.rsvp_status.as_deref() == Some("DECLINED")
                {
                    continue;
                }
                let Some(rrule) = m.event.rrule.clone() else {
                    continue;
                };
                let duration = m
                    .event
                    .ends_at
                    .map(|e| e - m.event.starts_at)
                    .unwrap_or(1_800_000);
                let Some(occs) = crate::caldav::rrule::expand(
                    &rrule,
                    m.event.starts_at,
                    duration,
                    m.ical_raw.as_deref(),
                    now,
                    now + lead_ms,
                ) else {
                    continue;
                };
                let Some(next) = occs.first().copied() else {
                    continue;
                };
                // Gate: skip when this occurrence was already notified,
                // and never re-notify the master's own start (handled
                // by upcoming_for_notify above).
                let already = db
                    .read({
                        let id = m.event.id;
                        move |conn| {
                            Ok(conn.query_row(
                                "SELECT COALESCE(notified_at, 0) FROM calendar_events WHERE id = ?1",
                                rusqlite::params![id],
                                |r| r.get::<_, i64>(0),
                            )?)
                        }
                    })
                    .await
                    .unwrap_or(i64::MAX);
                if already >= next.start || next.start <= m.event.starts_at {
                    continue;
                }
                let event_id = m.event.id;
                let _ = db
                    .write(move |conn| repo::calendar::set_notified(conn, event_id, next.start))
                    .await;
                let mut ev = m.event.clone();
                ev.starts_at = next.start;
                ev.ends_at = Some(next.end);
                bus.emit(CoreEvent::EventReminder {
                    event: ev,
                    occurrence_start: next.start,
                });
            }
        }
    }
}

/// Clear a due snooze and mark the thread's newest actionable message unread
/// so it pops. When that message was read, also enqueue the same `mark_unread`
/// pending action a manual "mark unread" produces: without it, flag
/// reconciliation would overwrite the local unread flag with the server's
/// \Seen a few minutes later. Returns the account to nudge when an action was
/// enqueued.
fn wake_thread(
    conn: &mut rusqlite::Connection,
    thread_id: i64,
) -> crate::error::Result<Option<i64>> {
    let tx = conn.transaction()?;
    repo::snoozes::clear(&tx, thread_id)?;
    // The message to pop unread is the newest one a manual "mark unread"
    // would sensibly hit: not a draft, not filed under a sent/drafts/trash/
    // spam role, and carrying a remote identity (folder + UID) the queue can
    // resolve. Anything else - a local draft, an unsynced just-sent copy -
    // would defer the action until it exhausts its retry budget. When no
    // message qualifies, fall back to the newest message overall so the wake
    // still pops locally; no server action is enqueued then.
    let actionable = tx
        .query_row(
            "SELECT m.id, m.is_read FROM messages m
             LEFT JOIN folders f ON f.id = m.folder_id
             WHERE m.thread_id = ?1 AND m.is_draft = 0
               AND COALESCE(f.role, '') NOT IN ('sent','drafts','trash','spam')
               AND m.folder_id IS NOT NULL AND m.uid IS NOT NULL AND m.uid > 0
             ORDER BY m.date DESC, m.id DESC LIMIT 1",
            rusqlite::params![thread_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?;
    let latest = if actionable.is_some() {
        None
    } else {
        tx.query_row(
            "SELECT id, is_read FROM messages WHERE thread_id = ?1
             ORDER BY date DESC, id DESC LIMIT 1",
            rusqlite::params![thread_id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?
    };
    let mut nudged = None;
    if let Some((msg_id, was_read)) = actionable.or(latest) {
        repo::messages::set_read(&tx, msg_id, false)?;
        if actionable.is_some() && was_read != 0 {
            let account_id: i64 = tx.query_row(
                "SELECT account_id FROM threads WHERE id = ?1",
                rusqlite::params![thread_id],
                |r| r.get(0),
            )?;
            repo::actions::enqueue(
                &tx,
                account_id,
                "mark_unread",
                Some(msg_id),
                Some(thread_id),
                &repo::actions::identity_payload(&tx, msg_id)?,
                None,
            )?;
            nudged = Some(account_id);
        }
    }
    repo::threads::recompute(&tx, thread_id)?;
    tx.commit()?;
    Ok(nudged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testutil;
    use rusqlite::Connection;

    #[test]
    fn wake_enqueues_mark_unread_for_a_previously_read_message() {
        let mut conn = testutil::conn();
        testutil::seed_account(&conn);
        let (thread_id, msg_id) = testutil::seed_message(&conn, "a@b.c", "subj", false);
        // The user read the thread before snoozing it.
        repo::messages::set_read(&conn, msg_id, true).unwrap();
        repo::snoozes::set(&conn, thread_id, 1, 1, Some(1)).unwrap();

        let nudged = wake_thread(&mut conn, thread_id).unwrap();
        assert_eq!(nudged, Some(1));

        assert!(repo::snoozes::woken(&conn, i64::MAX).unwrap().is_empty());
        let is_read: i64 = conn
            .query_row(
                "SELECT is_read FROM messages WHERE id = ?1",
                [msg_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(is_read, 0, "woken thread pops back as unread");
        assert!(
            repo::actions::has_pending_for_message(&conn, msg_id).unwrap(),
            "pending mark_unread protects the flag from reconcile_flags"
        );
        let action = repo::actions::get(
            &conn,
            conn.query_row(
                "SELECT id FROM pending_actions WHERE message_id = ?1 AND kind = 'mark_unread'",
                [msg_id],
                |r| r.get(0),
            )
            .unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(action.thread_id, Some(thread_id));
        assert_eq!(action.payload["folderId"].as_i64(), Some(1));
        // seed_message stores uid = thread_id.
        assert_eq!(action.payload["uid"].as_i64(), Some(thread_id));

        // A repeated wake finds no snooze and an already-unread message:
        // nothing is enqueued twice.
        assert_eq!(wake_thread(&mut conn, thread_id).unwrap(), None);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM pending_actions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    /// Fields for an extra message in a thread; `folder_id`/`uid` of None
    /// model a local-only copy with no remote identity yet.
    #[derive(Default)]
    struct ExtraMsg {
        folder_id: Option<i64>,
        uid: Option<i64>,
        date: i64,
        is_read: bool,
        is_draft: bool,
        is_outgoing: bool,
    }

    fn add_message(conn: &Connection, thread_id: i64, m: ExtraMsg) -> i64 {
        conn.execute(
            "INSERT INTO messages (thread_id, account_id, folder_id, uid, message_id,
             subject, from_addr, date, is_read, is_automated, is_draft, is_outgoing)
             VALUES (?1, 1, ?2, ?3, 'mid-x' || ?4, 'subj', 'a@b.c', ?4, ?5, 0, ?6, ?7)",
            rusqlite::params![
                thread_id,
                m.folder_id,
                m.uid,
                m.date,
                m.is_read as i64,
                m.is_draft as i64,
                m.is_outgoing as i64
            ],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn is_read(conn: &Connection, msg_id: i64) -> i64 {
        conn.query_row(
            "SELECT is_read FROM messages WHERE id = ?1",
            [msg_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn wake_skips_a_draft_latest_message_for_the_remote_action() {
        let mut conn = testutil::conn();
        testutil::seed_account(&conn);
        let (thread_id, received) = testutil::seed_message(&conn, "a@b.c", "subj", false);
        repo::messages::set_read(&conn, received, true).unwrap();
        // Newest message is a local draft: it must not be the mark_unread
        // target, and marking it unread would not even pop the thread.
        let draft = add_message(
            &conn,
            thread_id,
            ExtraMsg {
                folder_id: Some(1),
                uid: Some(777),
                date: 2000,
                is_read: true,
                is_draft: true,
                ..Default::default()
            },
        );
        repo::snoozes::set(&conn, thread_id, 1, 1, Some(1)).unwrap();

        assert_eq!(wake_thread(&mut conn, thread_id).unwrap(), Some(1));
        assert_eq!(is_read(&conn, draft), 1, "draft keeps its own read flag");
        assert_eq!(is_read(&conn, received), 0, "received message pops unread");
        let target: i64 = conn
            .query_row(
                "SELECT message_id FROM pending_actions WHERE kind = 'mark_unread'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(target, received);
    }

    #[test]
    fn wake_skips_a_sent_latest_message_for_the_remote_action() {
        let mut conn = testutil::conn();
        testutil::seed_account(&conn);
        conn.execute(
            "INSERT INTO folders (id, account_id, imap_name, role) VALUES (2,1,'Sent','sent')",
            [],
        )
        .unwrap();
        let (thread_id, received) = testutil::seed_message(&conn, "a@b.c", "subj", false);
        repo::messages::set_read(&conn, received, true).unwrap();
        // The user's own just-sent reply sits on top; it has a UID but lives
        // in the sent folder, so the flag push targets the received copy.
        let sent = add_message(
            &conn,
            thread_id,
            ExtraMsg {
                folder_id: Some(2),
                uid: Some(888),
                date: 2000,
                is_read: true,
                is_outgoing: true,
                ..Default::default()
            },
        );
        repo::snoozes::set(&conn, thread_id, 1, 1, Some(1)).unwrap();

        assert_eq!(wake_thread(&mut conn, thread_id).unwrap(), Some(1));
        assert_eq!(is_read(&conn, sent), 1, "sent copy is not flipped unread");
        assert_eq!(is_read(&conn, received), 0);
        let target: i64 = conn
            .query_row(
                "SELECT message_id FROM pending_actions WHERE kind = 'mark_unread'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(target, received);
    }

    #[test]
    fn wake_without_any_remote_identity_still_succeeds_locally() {
        let mut conn = testutil::conn();
        testutil::seed_account(&conn);
        let (thread_id, msg_id) = testutil::seed_message(&conn, "a@b.c", "subj", false);
        repo::messages::set_read(&conn, msg_id, true).unwrap();
        // No folder/UID: nothing the queue could ever resolve remotely.
        conn.execute(
            "UPDATE messages SET folder_id = NULL, uid = NULL WHERE id = ?1",
            [msg_id],
        )
        .unwrap();
        repo::snoozes::set(&conn, thread_id, 1, 1, Some(1)).unwrap();

        assert_eq!(wake_thread(&mut conn, thread_id).unwrap(), None);
        assert!(repo::snoozes::woken(&conn, i64::MAX).unwrap().is_empty());
        assert_eq!(is_read(&conn, msg_id), 0, "local pop still happens");
        assert!(!repo::actions::has_pending_for_message(&conn, msg_id).unwrap());
    }

    #[test]
    fn wake_of_an_unread_message_enqueues_nothing() {
        let mut conn = testutil::conn();
        testutil::seed_account(&conn);
        let (thread_id, msg_id) = testutil::seed_message(&conn, "a@b.c", "subj", false);
        repo::snoozes::set(&conn, thread_id, 1, 1, Some(1)).unwrap();

        assert_eq!(wake_thread(&mut conn, thread_id).unwrap(), None);
        assert!(repo::snoozes::woken(&conn, i64::MAX).unwrap().is_empty());
        let is_read: i64 = conn
            .query_row(
                "SELECT is_read FROM messages WHERE id = ?1",
                [msg_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(is_read, 0);
        assert!(!repo::actions::has_pending_for_message(&conn, msg_id).unwrap());
    }
}
