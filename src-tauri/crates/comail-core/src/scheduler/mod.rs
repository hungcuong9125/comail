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

/// Each recurring master is expanded at most once per cache span instead of
/// once per tick: an entry answers every tick window [t, t+lead] with
/// t in [expanded_at, covers_until] because it was expanded over
/// [expanded_at, expanded_at + lead + SPAN], a superset. Long enough to cut
/// expansion work ~100x, short enough that edits, syncs and DST transitions
/// always refresh quickly.
const REMINDER_CACHE_SPAN_MS: i64 = 10 * 60_000;

/// Per-tick reminder state that outlives a single tick.
#[derive(Default)]
struct TickCache {
    /// Raw settings JSON seen at the last tick that parsed it, and the lead
    /// minutes it produced. The tick re-reads the row every 5s but only
    /// re-parses (and re-runs `get`'s migrations) when the text changed.
    settings_raw: Option<String>,
    lead_min: Option<i64>,
    /// Local UTC offset when the entries below were expanded. Recurrence
    /// times are computed against `chrono::Local`, so a timezone change or
    /// a DST transition observed here forces a full re-expansion.
    tz_offset_ms: Option<i64>,
    /// Lead window the current entries were expanded for; a settings change
    /// to `meeting_notify_lead_minutes` invalidates them all.
    lead_ms: Option<i64>,
    entries: HashMap<i64, MasterCache>,
}

/// One cached expansion of a recurring master.
struct MasterCache {
    /// The master fields `expand` reads: any change (sync update, edited
    /// invite, new EXDATE in `ical_raw`) must re-expand.
    rrule: String,
    starts_at: i64,
    ends_at: Option<i64>,
    ical_raw: Option<String>,
    /// Tick instant this entry was expanded; occurrences cover
    /// [expanded_at, expanded_at + lead + SPAN]. A clock set backwards makes
    /// `now` fall below `expanded_at` and forces a re-expand too.
    expanded_at: i64,
    /// Last `now` this entry can answer (= expanded_at + SPAN).
    covers_until: i64,
    occs: Vec<crate::caldav::rrule::Occurrence>,
}

impl MasterCache {
    fn matches(&self, m: &repo::calendar::SyncRow, now: i64) -> bool {
        self.expanded_at <= now
            && now <= self.covers_until
            && self.rrule == m.event.rrule.as_deref().unwrap_or("")
            && self.starts_at == m.event.starts_at
            && self.ends_at == m.event.ends_at
            && self.ical_raw == m.ical_raw
    }
}

impl TickCache {
    fn local_offset_ms() -> i64 {
        chrono::Local::now().offset().local_minus_utc() as i64 * 1000
    }

    /// Invalidate the expansion cache when the environment shifted and drop
    /// entries for masters that left the set (deleted, removed account).
    fn begin_scan(&mut self, lead_ms: i64, masters: &[repo::calendar::SyncRow]) {
        let tz = Self::local_offset_ms();
        if self.lead_ms != Some(lead_ms) || self.tz_offset_ms != Some(tz) {
            self.entries.clear();
            self.lead_ms = Some(lead_ms);
            self.tz_offset_ms = Some(tz);
        }
        let ids: std::collections::HashSet<i64> = masters.iter().map(|m| m.event.id).collect();
        self.entries.retain(|id, _| ids.contains(id));
    }

    /// First occurrence overlapping [now, now + lead_ms), expanding the
    /// master over the wider cache span when the entry is missing or stale.
    /// Expansions that return None are not cached - a window-dependent None
    /// would be wrong to reuse, and unsupported rules simply retry each
    /// tick exactly as before.
    fn next_occurrence(
        &mut self,
        m: &repo::calendar::SyncRow,
        now: i64,
        lead_ms: i64,
    ) -> Option<crate::caldav::rrule::Occurrence> {
        // Same gates as upcoming_for_notify: cancelled series (incl. CANCEL
        // tombstones) and declined invites are silent.
        if m.event.status.as_deref() == Some("CANCELLED")
            || m.event.rsvp_status.as_deref() == Some("DECLINED")
        {
            return None;
        }
        let rrule = m.event.rrule.clone()?;
        if !self
            .entries
            .get(&m.event.id)
            .is_some_and(|e| e.matches(m, now))
        {
            let duration = m
                .event
                .ends_at
                .map(|e| e - m.event.starts_at)
                .unwrap_or(1_800_000);
            match crate::caldav::rrule::expand(
                &rrule,
                m.event.starts_at,
                duration,
                m.ical_raw.as_deref(),
                now,
                now + lead_ms + REMINDER_CACHE_SPAN_MS,
            ) {
                Some(occs) => {
                    self.entries.insert(
                        m.event.id,
                        MasterCache {
                            rrule,
                            starts_at: m.event.starts_at,
                            ends_at: m.event.ends_at,
                            ical_raw: m.ical_raw.clone(),
                            expanded_at: now,
                            covers_until: now + REMINDER_CACHE_SPAN_MS,
                            occs,
                        },
                    );
                }
                // Not cached: a window-dependent None could be wrong for the
                // next window, so an unsupported rule retries every tick as
                // before. A stale entry must go with it.
                None => {
                    self.entries.remove(&m.event.id);
                }
            }
        }
        self.entries
            .get(&m.event.id)?
            .occs
            .iter()
            .copied()
            .find(|o| o.end > now && o.start < now + lead_ms)
    }
}

/// The per-tick settings read: the row is fetched every time, but the JSON
/// is parsed (and `get`'s field migrations run) only when its text changed
/// or was never parsed. `None` means "unchanged, use the cached lead".
fn settings_lead_step(
    conn: &rusqlite::Connection,
    needs_parse: bool,
    prev_raw: &Option<String>,
) -> crate::error::Result<Option<(Option<String>, i64)>> {
    let raw = repo::settings::raw_json(conn)?;
    if !needs_parse && &raw == prev_raw {
        return Ok(None);
    }
    Ok(Some((
        raw,
        repo::settings::get(conn)?.meeting_notify_lead_minutes,
    )))
}

/// Recurring masters due a reminder in [now, now + lead_ms): the masters and
/// their notified_at arrive in a single SELECT (the old code issued one
/// per master), and expansions come from the per-tick cache.
fn due_recurring_reminders(
    conn: &rusqlite::Connection,
    cache: &mut TickCache,
    now: i64,
    lead_ms: i64,
) -> crate::error::Result<Vec<(repo::calendar::SyncRow, crate::caldav::rrule::Occurrence)>> {
    let masters = repo::calendar::recurring_masters(conn, now + lead_ms)?;
    cache.begin_scan(lead_ms, &masters);
    let mut due = Vec::new();
    for m in &masters {
        let Some(next) = cache.next_occurrence(m, now, lead_ms) else {
            continue;
        };
        // Skip when this occurrence was already notified, and never re-notify
        // the master's own start (handled by upcoming_for_notify above).
        let already = m.notified_at.unwrap_or(0);
        if already >= next.start || next.start <= m.event.starts_at {
            continue;
        }
        due.push((m.clone(), next));
    }
    Ok(due)
}

pub fn spawn(
    db: Db,
    bus: EventBus,
    handles: Arc<RwLock<HashMap<i64, AccountHandle>>>,
    cal_handles: Arc<RwLock<HashMap<i64, CalTaskHandle>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut nudged_until: i64 = 0;
        let mut cache = TickCache::default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(TICK_SECS)).await;
            // A panic in one tick (e.g. on hostile calendar data) must not end
            // the loop: snooze wake-ups, send-later and reminders all ride on it.
            let ticked = AssertUnwindSafe(tick(
                &db,
                &bus,
                &handles,
                &cal_handles,
                &mut nudged_until,
                &mut cache,
            ))
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
    cache: &mut TickCache,
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
    // window. The settings row is re-read every tick (cheap text fetch)
    // but parsed only when it changed; recurring masters arrive with
    // their notified_at in one query and expand at most once per
    // REMINDER_CACHE_SPAN_MS, never late: a reminder that would fire at
    // tick t still fires at tick t.
    let needs_parse = cache.lead_min.is_none();
    let prev_raw = cache.settings_raw.clone();
    let lead_step = db
        .read(move |conn| settings_lead_step(conn, needs_parse, &prev_raw))
        .await;
    match lead_step {
        Err(_) => {} // same as the old unwrap_or(0): no reminders this tick
        Ok(step) => {
            if let Some((raw, lead)) = step {
                cache.settings_raw = raw;
                cache.lead_min = Some(lead);
            }
            let lead_min = cache.lead_min.unwrap_or(0);
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
                // The cache is checked out into the job and returned with
                // the result so it can live across ticks on this task.
                let checked_out = std::mem::take(cache);
                if let Ok((mut c, due)) = db
                    .read(move |conn| {
                        let mut c = checked_out;
                        let due = due_recurring_reminders(conn, &mut c, now, lead_ms)?;
                        Ok((c, due))
                    })
                    .await
                {
                    std::mem::swap(cache, &mut c);
                    for (m, next) in due {
                        let event_id = m.event.id;
                        let _ = db
                            .write(move |conn| {
                                repo::calendar::set_notified(conn, event_id, next.start)
                            })
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
    use chrono::TimeZone;
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

    // ---- Reminder scan: reference implementation + equivalence tests ------

    fn local_ms(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> i64 {
        chrono::Local
            .from_local_datetime(
                &chrono::NaiveDate::from_ymd_opt(y, mo, d)
                    .unwrap()
                    .and_hms_opt(h, mi, 0)
                    .unwrap(),
            )
            .earliest()
            .unwrap()
            .timestamp_millis()
    }

    const HOUR_MS: i64 = 3_600_000;
    const DAY_MS: i64 = 86_400_000;

    /// Insert a local calendar event, then attach recurrence fields.
    fn seed_event(
        c: &Connection,
        uid: &str,
        starts_at: i64,
        duration_ms: i64,
        rrule: Option<&str>,
        ical_raw: Option<&str>,
    ) -> i64 {
        let id = repo::calendar::insert_local(
            c,
            1,
            None,
            uid,
            uid,
            None,
            None,
            None,
            "a@b.c",
            &[],
            starts_at,
            starts_at + duration_ms,
            false,
        )
        .unwrap();
        c.execute(
            "UPDATE calendar_events SET rrule = ?2, ical_raw = ?3 WHERE id = ?1",
            rusqlite::params![id, rrule, ical_raw],
        )
        .unwrap();
        id
    }

    /// The pre-optimisation tick logic verbatim: masters in one query, every
    /// master re-expanded every tick, and a separate notified_at SELECT for
    /// each master that reaches the gate.
    fn reference_due(conn: &Connection, now: i64, lead_ms: i64) -> Vec<(i64, i64, i64)> {
        let masters = repo::calendar::recurring_masters(conn, now + lead_ms).unwrap();
        let mut out = Vec::new();
        for m in masters {
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
            let already: i64 = conn
                .query_row(
                    "SELECT COALESCE(notified_at, 0) FROM calendar_events WHERE id = ?1",
                    rusqlite::params![m.event.id],
                    |r| r.get(0),
                )
                .unwrap();
            if already >= next.start || next.start <= m.event.starts_at {
                continue;
            }
            out.push((m.event.id, next.start, next.end));
        }
        out
    }

    fn new_due(
        conn: &Connection,
        cache: &mut TickCache,
        now: i64,
        lead_ms: i64,
    ) -> Vec<(i64, i64, i64)> {
        due_recurring_reminders(conn, cache, now, lead_ms)
            .unwrap()
            .iter()
            .map(|(m, o)| (m.event.id, o.start, o.end))
            .collect()
    }

    /// A busy calendar: every-day/weekly/monthly series, a finite COUNT
    /// series that dies mid-window, EXDATE + RECURRENCE-ID overrides, a
    /// multi-day meeting, an unsupported rule, cancelled and declined
    /// series, a plain one-off, and a master starting inside the window.
    fn seed_busy_calendar(c: &Connection, base: i64) -> Vec<i64> {
        // EXDATE one occurrence, RECURRENCE-ID moves another.
        let ex = chrono::Local
            .timestamp_millis_opt(base + 3 * DAY_MS)
            .earliest()
            .unwrap()
            .with_timezone(&chrono::Utc)
            .format("%Y%m%dT%H%M%SZ")
            .to_string();
        let ovr = chrono::Local
            .timestamp_millis_opt(base + 6 * DAY_MS)
            .earliest()
            .unwrap()
            .with_timezone(&chrono::Utc)
            .format("%Y%m%dT%H%M%SZ")
            .to_string();
        let raw = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:m1\r\nDTSTART:20260201T090000\r\nRRULE:FREQ=WEEKLY\r\nEXDATE:{ex}\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:m1\r\nRECURRENCE-ID:{ovr}\r\nDTSTART:{ovr}\r\nDTEND:{ovr}\r\nSUMMARY:moved\r\nEND:VEVENT\r\nEND:VCALENDAR"
        );
        let cancelled = seed_event(
            c,
            "cancelled",
            base - 5 * DAY_MS,
            HOUR_MS,
            Some("FREQ=DAILY"),
            None,
        );
        c.execute(
            "UPDATE calendar_events SET status = 'CANCELLED' WHERE id = ?1",
            [cancelled],
        )
        .unwrap();
        let declined = seed_event(
            c,
            "declined",
            base - 5 * DAY_MS,
            HOUR_MS,
            Some("FREQ=DAILY"),
            None,
        );
        c.execute(
            "UPDATE calendar_events SET rsvp_status = 'DECLINED' WHERE id = ?1",
            [declined],
        )
        .unwrap();
        // Non-recurring one-off: invisible to recurring_masters.
        seed_event(c, "oneoff", base + HOUR_MS, HOUR_MS, None, None);
        vec![
            seed_event(
                c,
                "daily",
                base - 10 * DAY_MS,
                HOUR_MS,
                Some("FREQ=DAILY"),
                None,
            ),
            seed_event(
                c,
                "weekdays",
                base - 30 * DAY_MS,
                HOUR_MS,
                Some("FREQ=WEEKLY;BYDAY=MO,WE,FR"),
                None,
            ),
            seed_event(
                c,
                "monthly",
                base - 90 * DAY_MS,
                2 * HOUR_MS,
                Some("FREQ=MONTHLY;BYDAY=1MO"),
                None,
            ),
            seed_event(
                c,
                "finite",
                base - DAY_MS,
                HOUR_MS,
                Some("FREQ=DAILY;COUNT=6"),
                None,
            ),
            seed_event(
                c,
                "exdates",
                base - 28 * DAY_MS,
                HOUR_MS,
                Some("FREQ=WEEKLY"),
                Some(&raw),
            ),
            // A 26-hour event: occurrences overlap window edges without
            // starting inside them.
            seed_event(
                c,
                "marathon",
                base - 40 * DAY_MS,
                26 * HOUR_MS,
                Some("FREQ=DAILY"),
                None,
            ),
            seed_event(
                c,
                "unsupported",
                base - DAY_MS,
                HOUR_MS,
                Some("FREQ=WEEKLY;BYSETPOS=2"),
                None,
            ),
            // Master whose own start falls inside a later scan window: the
            // `next.start <= starts_at` gate must keep it silent here (it is
            // upcoming_for_notify's job).
            seed_event(
                c,
                "futuremaster",
                base + 4 * DAY_MS,
                HOUR_MS,
                Some("FREQ=DAILY"),
                None,
            ),
        ]
    }

    /// Every simulated tick must produce exactly the reference decisions:
    /// a reminder never fires early, late, or twice.
    #[test]
    fn reminder_decisions_match_reference_across_ticks() {
        let c = testutil::conn();
        testutil::seed_account(&c);
        let base = local_ms(2026, 3, 1, 9, 0); // range straddles a US DST change
        seed_busy_calendar(&c, base);
        let lead = 10 * 60_000;
        let mut cache = TickCache::default();

        // Pre-notify the daily master for one mid-range occurrence: that slot
        // stays silent, later ones still fire.
        let daily_id: i64 = c
            .query_row(
                "SELECT id FROM calendar_events WHERE ical_uid='daily'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        repo::calendar::set_notified(&c, daily_id, base + 5 * DAY_MS).unwrap();

        let mut ticks: Vec<i64> = Vec::new();
        // Coarse sweep across two cache spans (the range includes Mar 8, the
        // US DST start, wherever the local zone observes one).
        let mut t = base - 2 * DAY_MS;
        while t < base + 12 * DAY_MS {
            ticks.push(t);
            t += 30 * 60_000;
        }
        // Tick-granularity sweep inside one cache span.
        let mut t = base + DAY_MS;
        while t < base + DAY_MS + 2 * HOUR_MS {
            ticks.push(t);
            t += 5_000;
        }
        // Sleep/wake jumps: hours forward, then days past the cache span.
        ticks.push(base + 14 * DAY_MS);
        ticks.push(base + 14 * DAY_MS + 5_000);

        for now in ticks {
            let want = reference_due(&c, now, lead);
            let got = new_due(&c, &mut cache, now, lead);
            assert_eq!(got, want, "tick at now={now} diverged");
            // Like the real tick: mark every fired occurrence notified.
            for (id, start, _) in &got {
                repo::calendar::set_notified(&c, *id, *start).unwrap();
            }
        }
    }

    /// The per-master notified_at SELECT and per-tick re-expansion are gone:
    /// a warm-cache scan executes exactly one statement (the masters SELECT).
    #[test]
    fn reminder_scan_uses_one_query_per_tick() {
        use rusqlite::trace::TraceEventCodes;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static STMTS: AtomicUsize = AtomicUsize::new(0);

        let c = testutil::conn();
        testutil::seed_account(&c);
        let base = local_ms(2026, 3, 1, 9, 0);
        let masters = seed_busy_calendar(&c, base).len();
        let lead = 10 * 60_000;
        let now = base - HOUR_MS;
        let mut cache = TickCache::default();

        c.trace_v2(
            TraceEventCodes::SQLITE_TRACE_STMT,
            Some(|_| {
                STMTS.fetch_add(1, Ordering::SeqCst);
            }),
        );

        // Cold scan: one query, expansions in-process.
        STMTS.store(0, Ordering::SeqCst);
        let cold = new_due(&c, &mut cache, now, lead);
        assert_eq!(STMTS.load(Ordering::SeqCst), 1, "cold scan statements");

        // Warm scan: still one query, and the same decision as the
        // reference for that instant.
        STMTS.store(0, Ordering::SeqCst);
        let warm = new_due(&c, &mut cache, now + 5_000, lead);
        assert_eq!(STMTS.load(Ordering::SeqCst), 1, "warm scan statements");
        assert_eq!(warm, reference_due(&c, now + 5_000, lead));

        // The reference does the N+1: one SELECT per master reaching the
        // notified_at gate.
        STMTS.store(0, Ordering::SeqCst);
        let reference = reference_due(&c, now, lead);
        let ref_stmts = STMTS.load(Ordering::SeqCst);
        c.trace_v2(TraceEventCodes::empty(), None);
        assert!(
            ref_stmts > 1,
            "reference should re-query per master ({ref_stmts} for {masters} masters)"
        );
        // Equivalent decision sets.
        assert_eq!(cold, reference);
    }

    /// Edited series, deleted rows, new invites and lead-minute changes are
    /// picked up without waiting for the cache span to expire.
    #[test]
    fn reminder_cache_invalidates_on_change() {
        let c = testutil::conn();
        testutil::seed_account(&c);
        let base = local_ms(2026, 3, 1, 9, 0);
        let id = seed_event(
            &c,
            "daily",
            base - 10 * DAY_MS,
            HOUR_MS,
            Some("FREQ=DAILY"),
            None,
        );
        let lead = 10 * 60_000;
        let now = base - HOUR_MS;
        let mut cache = TickCache::default();

        let first = new_due(&c, &mut cache, now, lead);
        assert_eq!(first, reference_due(&c, now, lead));

        // The rule changes between ticks (sync wrote an updated invite):
        // the cached occurrences must not answer for the new rule.
        c.execute(
            "UPDATE calendar_events SET rrule = 'FREQ=WEEKLY' WHERE id = ?1",
            [id],
        )
        .unwrap();
        assert_eq!(
            new_due(&c, &mut cache, now + 5_000, lead),
            reference_due(&c, now + 5_000, lead)
        );

        // An EXDATE arriving in ical_raw likewise re-expands.
        c.execute(
            "UPDATE calendar_events SET ical_raw = 'BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:d\r\nEXDATE:29990101T000000Z\r\nEND:VEVENT\r\nEND:VCALENDAR' WHERE id = ?1",
            [id],
        )
        .unwrap();
        assert_eq!(
            new_due(&c, &mut cache, now + 10_000, lead),
            reference_due(&c, now + 10_000, lead)
        );

        // A new master synced mid-span is picked up on the next tick.
        seed_event(
            &c,
            "newguy",
            base - DAY_MS,
            HOUR_MS,
            Some("FREQ=DAILY"),
            None,
        );
        assert_eq!(
            new_due(&c, &mut cache, now + 15_000, lead),
            reference_due(&c, now + 15_000, lead)
        );

        // Deleting the master drops it (and its cache entry) immediately.
        c.execute("DELETE FROM calendar_events WHERE id = ?1", [id])
            .unwrap();
        let after_delete = new_due(&c, &mut cache, now + 20_000, lead);
        assert!(!after_delete.iter().any(|(eid, _, _)| *eid == id));
        assert_eq!(after_delete, reference_due(&c, now + 20_000, lead));

        // A lead-minutes change re-expands for the new window.
        let longer = new_due(&c, &mut cache, now + 25_000, 40 * 60_000);
        assert_eq!(longer, reference_due(&c, now + 25_000, 40 * 60_000));

        // A forged timezone shift clears the cache (the entry would answer a
        // stale occurrence otherwise); decisions still match the reference.
        cache.tz_offset_ms = Some(i64::MAX);
        assert_eq!(
            new_due(&c, &mut cache, now + 30_000, 40 * 60_000),
            reference_due(&c, now + 30_000, 40 * 60_000)
        );
    }

    /// The settings row is read every tick but only parsed when the text
    /// changed; an absent row behaves like `get` (defaults).
    #[test]
    fn settings_step_parses_only_on_change() {
        let c = testutil::conn();
        // No row yet: first call parses defaults (lead 10), second does not.
        let first = settings_lead_step(&c, true, &None).unwrap().unwrap();
        assert_eq!(first.1, 10);
        assert_eq!(first.0, None);
        assert!(settings_lead_step(&c, false, &first.0).unwrap().is_none());

        let s = crate::models::Settings {
            meeting_notify_lead_minutes: 7,
            ..Default::default()
        };
        repo::settings::set(&c, &s).unwrap();
        let second = settings_lead_step(&c, false, &first.0).unwrap().unwrap();
        assert_eq!(second.1, 7);
        assert!(settings_lead_step(&c, false, &second.0).unwrap().is_none());

        let s = crate::models::Settings {
            meeting_notify_lead_minutes: 3,
            ..s
        };
        repo::settings::set(&c, &s).unwrap();
        let third = settings_lead_step(&c, false, &second.0).unwrap().unwrap();
        assert_eq!(third.1, 3);
        // A whitespace-only change still reparses (byte comparison), which is
        // what the old every-tick parse did too - same lead either way.
        c.execute(
            "UPDATE app_settings SET value = value || ' ' WHERE key = 'settings'",
            [],
        )
        .unwrap();
        let fourth = settings_lead_step(&c, false, &third.0).unwrap().unwrap();
        assert_eq!(fourth.1, 3);
    }
}
