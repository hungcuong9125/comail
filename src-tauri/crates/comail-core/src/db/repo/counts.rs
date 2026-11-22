//! Exact unread counts for split tabs and sidebar rows: a handful of scalar
//! COUNT queries sharing the predicate shapes of `threads::list`. Kept out of
//! threads.rs so the two evolve independently.

use crate::error::Result;
use crate::models::{Label, SplitRule, TabTotals, UnreadCounts};
use rusqlite::Connection;
use std::collections::HashMap;

/// Composable COUNT(*) query over threads (+ snoozes join, like SUMMARY_SELECT).
/// Kept as the test oracle for the grouped implementation below.
#[cfg(test)]
struct Q {
    clauses: Vec<String>,
    bind: Vec<Box<dyn rusqlite::types::ToSql>>,
    unread_only: bool,
}

#[cfg(test)]
impl Q {
    /// Base: threads with unread messages, optionally account-scoped.
    fn unread(account_id: Option<i64>) -> Self {
        let mut q = Q {
            clauses: Vec::new(),
            bind: Vec::new(),
            unread_only: true,
        };
        if let Some(acc) = account_id {
            q.bind.push(Box::new(acc));
            q.clauses.push(format!("t.account_id = ?{}", q.bind.len()));
        }
        q
    }

    /// Same base without the unread filter (drafts badge counts all drafts).
    fn any(account_id: Option<i64>) -> Self {
        let mut q = Q {
            clauses: Vec::new(),
            bind: Vec::new(),
            unread_only: false,
        };
        if let Some(acc) = account_id {
            q.bind.push(Box::new(acc));
            q.clauses.push(format!("t.account_id = ?{}", q.bind.len()));
        }
        q
    }

    fn clause(mut self, c: impl Into<String>) -> Self {
        self.clauses.push(c.into());
        self
    }

    /// Membership as `t.id IN (…)` rather than a correlated `EXISTS`: SQLite
    /// builds the folder's thread set once through the folder index, instead
    /// of probing every thread in the database (the inbox holds dozens of
    /// threads; the database can hold 100k+). Same rows either way.
    fn role_exists(&mut self, role: &str) -> String {
        self.bind.push(Box::new(role.to_string()));
        format!(
            "t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id = m.folder_id
                      WHERE f.role = ?{} AND m.thread_id IS NOT NULL)",
            self.bind.len()
        )
    }

    fn inbox(mut self) -> Self {
        let c = self.role_exists(crate::models::roles::INBOX);
        self.clauses.push(c);
        if self.unread_only {
            self.clauses.push("t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id=m.folder_id WHERE m.is_read=0 AND f.role='inbox')".into());
            self.unread_only = false;
        }
        self.clauses.push("s.thread_id IS NULL".into());
        self
    }

    /// Important (`automated=false`) / Other (`automated=true`) default buckets:
    /// forced by a routing rule, or unrouted mail split by the newest incoming
    /// message. Mirrors the bucket clauses in `threads::list`.
    fn bucket(mut self, automated: bool) -> Self {
        let (want, forced) = if automated {
            (1, "other")
        } else {
            (0, "important")
        };
        self.clauses.push(format!(
            "(t.routed_tab = '{forced}'
              OR ((t.routed_tab IS NULL OR t.routed_tab = 'pending')
                  AND (SELECT m.is_automated FROM visible_messages m
                       WHERE m.thread_id = t.id AND m.is_draft = 0 AND m.is_outgoing = 0
                       ORDER BY m.date DESC, m.id DESC LIMIT 1) = {want}))"
        ));
        self
    }

    /// A custom split tab: threads routed to `split:<id>`.
    fn routed_split(mut self, id: i64) -> Self {
        self.bind.push(Box::new(format!("split:{id}")));
        self.clauses
            .push(format!("t.routed_tab = ?{}", self.bind.len()));
        self
    }

    /// An auto-category tab: threads routed to `label:<id>`.
    fn routed_label(mut self, id: i64) -> Self {
        self.bind.push(Box::new(format!("label:{id}")));
        self.clauses
            .push(format!("t.routed_tab = ?{}", self.bind.len()));
        self
    }

    /// A manual (user) label: a cross-cutting membership filter, not a routed tab.
    fn label(mut self, label_id: i64) -> Self {
        self.bind.push(Box::new(label_id));
        self.clauses.push(format!(
            "EXISTS (SELECT 1 FROM message_labels ml JOIN visible_messages m ON m.id = ml.message_id
                     WHERE m.thread_id = t.id AND ml.label_id = ?{})",
            self.bind.len()
        ));
        self
    }

    fn run(mut self, conn: &Connection) -> Result<i64> {
        if self.unread_only {
            self.clauses.push("t.id IN (SELECT m.thread_id FROM visible_messages m LEFT JOIN folders f ON f.id=m.folder_id WHERE m.is_read=0 AND COALESCE(f.role,'') NOT IN ('trash','spam'))".into());
        }
        let where_sql = if self.clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", self.clauses.join(" AND "))
        };
        let sql = format!(
            "SELECT COUNT(*) FROM threads t LEFT JOIN snoozes s ON s.thread_id = t.id {where_sql}"
        );
        let params: Vec<&dyn rusqlite::types::ToSql> =
            self.bind.iter().map(|b| b.as_ref()).collect();
        // The SQL text is fixed per caller (two variants: account-scoped or
        // not), so the cached statement survives every `mail:updated` refetch.
        Ok(conn
            .prepare_cached(&sql)?
            .query_row(params.as_slice(), |r| r.get(0))?)
    }
}

/// One standalone COUNT(*) badge for the sidebar views. The four views have
/// disjoint scopes, so each keeps its own query; the SQL text is fixed per
/// caller, so the cached statement survives every `mail:updated` refetch.
fn badge_count(
    conn: &Connection,
    account_id: Option<i64>,
    unread: bool,
    clauses: &[&str],
) -> Result<i64> {
    let mut sql = format!(
        "SELECT COUNT(*) FROM threads t LEFT JOIN snoozes s ON s.thread_id = t.id WHERE {}",
        clauses.join(" AND ")
    );
    let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if unread {
        sql.push_str(" AND t.id IN (SELECT m.thread_id FROM visible_messages m LEFT JOIN folders f ON f.id=m.folder_id WHERE m.is_read=0 AND COALESCE(f.role,'') NOT IN ('trash','spam'))");
    }
    if let Some(acc) = account_id {
        bind.push(Box::new(acc));
        sql.push_str(&format!(" AND t.account_id = ?{}", bind.len()));
    }
    let params: Vec<&dyn rusqlite::types::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
    Ok(conn
        .prepare_cached(&sql)?
        .query_row(params.as_slice(), |r| r.get(0))?)
}

/// One row of the grouped inbox scan: routed tab, newest incoming
/// is_automated (NULL for routed mail), thread count.
type TabGroup = (Option<String>, Option<i64>, i64);

/// The unread-inbox scope every badge shares (threads with unread mail in the
/// inbox folder, not snoozed), plus the routed tab and — for unrouted threads
/// only — the automation flag of the newest incoming message. One grouped
/// scan replaces the separate COUNT(*) per tab (inbox, Important, Other and
/// every split/auto-label badge ran the same base scan).
fn inbox_tab_groups(
    conn: &Connection,
    account_id: Option<i64>,
    unread: bool,
) -> Result<Vec<TabGroup>> {
    let sql = inbox_tab_groups_sql(account_id.is_some(), unread);
    let params: &[&dyn rusqlite::types::ToSql] = match &account_id {
        Some(acc) => &[acc],
        None => &[],
    };
    let rows = conn
        .prepare_cached(&sql)?
        .query_map(params, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn inbox_tab_groups_sql(account_scoped: bool, unread: bool) -> String {
    // `newest_auto` is NULL for routed threads: the CASE skips the correlated
    // subquery, and the Important/Other buckets only look at unrouted mail.
    let mut sql = String::from(
        "SELECT t.routed_tab AS tab,
                CASE WHEN t.routed_tab IS NULL OR t.routed_tab = 'pending'
                     THEN (SELECT m.is_automated FROM visible_messages m
                           WHERE m.thread_id = t.id AND m.is_draft = 0 AND m.is_outgoing = 0
                           ORDER BY m.date DESC, m.id DESC LIMIT 1)
                END AS newest_auto,
                COUNT(*) AS n
         FROM threads t LEFT JOIN snoozes s ON s.thread_id = t.id
         WHERE t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id = m.folder_id
                        WHERE f.role = 'inbox' AND m.thread_id IS NOT NULL)
           AND s.thread_id IS NULL",
    );
    if unread {
        sql.push_str(
            " AND t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id=m.folder_id WHERE m.is_read=0 AND f.role='inbox')",
        );
    }
    if account_scoped {
        sql.push_str(" AND t.account_id = ?1");
    }
    sql.push_str(" GROUP BY tab, newest_auto");
    sql
}

/// Unread counts per routed tab without the unread filter — the `count_all`
/// split scope. Only queried when at least one split opts in.
fn routed_tab_totals(conn: &Connection, account_id: Option<i64>) -> Result<HashMap<String, i64>> {
    let mut sql = String::from(
        "SELECT t.routed_tab, COUNT(*) FROM threads t
         LEFT JOIN snoozes s ON s.thread_id = t.id
         WHERE t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id = m.folder_id
                        WHERE f.role = 'inbox' AND m.thread_id IS NOT NULL)
           AND s.thread_id IS NULL
           AND t.routed_tab IS NOT NULL",
    );
    let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(acc) = account_id {
        bind.push(Box::new(acc));
        sql.push_str(&format!(" AND t.account_id = ?{}", bind.len()));
    }
    sql.push_str(" GROUP BY t.routed_tab");
    let params: Vec<&dyn rusqlite::types::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
    let rows = conn
        .prepare_cached(&sql)?
        .query_map(params.as_slice(), |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<HashMap<String, i64>>>()?;
    Ok(rows)
}

/// Threads carrying each manual label, in one grouped pass. The old code ran
/// one COUNT(*) per label; an EXISTS membership test per label is a
/// `COUNT(DISTINCT t.id)` per label over the same join. Scope matches
/// View::All exactly: any thread with visible (non-trash/spam) mail,
/// archived and snoozed included, plus `unread`'s unread filter when set.
fn manual_label_counts(
    conn: &Connection,
    account_id: Option<i64>,
    label_ids: &[i64],
    unread: bool,
) -> Result<HashMap<i64, i64>> {
    if label_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = label_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let mut sql = format!(
        "SELECT ml.label_id, COUNT(DISTINCT t.id)
         FROM threads t
         JOIN message_labels ml ON ml.label_id IN ({placeholders})
         JOIN visible_messages m ON m.id = ml.message_id AND m.thread_id = t.id
         WHERE {}",
        super::threads::HAS_VISIBLE_MAIL
    );
    let mut bind: Vec<Box<dyn rusqlite::types::ToSql>> =
        label_ids.iter().map(|id| Box::new(*id) as _).collect();
    if unread {
        sql.push_str(
            " AND t.id IN (SELECT m2.thread_id FROM visible_messages m2 LEFT JOIN folders f2 ON f2.id=m2.folder_id WHERE m2.is_read=0 AND COALESCE(f2.role,'') NOT IN ('trash','spam'))",
        );
    }
    if let Some(acc) = account_id {
        bind.push(Box::new(acc));
        sql.push_str(&format!(" AND t.account_id = ?{}", bind.len()));
    }
    sql.push_str(" GROUP BY ml.label_id");
    let params: Vec<&dyn rusqlite::types::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
    let rows = conn
        .prepare_cached(&sql)?
        .query_map(params.as_slice(), |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<HashMap<i64, i64>>>()?;
    Ok(rows)
}

/// Fold one grouped scan into the badge fields: every row is an inbox
/// thread, Important/Other split unrouted mail by the newest incoming
/// message, and each custom routed tab keeps its own count.
fn fold_tab_groups(groups: &[TabGroup]) -> (i64, i64, i64, HashMap<String, i64>) {
    let (mut inbox, mut important, mut other) = (0, 0, 0);
    let mut routed: HashMap<String, i64> = HashMap::new();
    for (tab, auto, n) in groups {
        inbox += n;
        match tab.as_deref() {
            Some("important") => important += n,
            Some("other") => other += n,
            None | Some("pending") => match auto {
                Some(0) => important += n,
                Some(1) => other += n,
                _ => {}
            },
            Some(t) => {
                routed.insert(t.to_string(), *n);
            }
        }
    }
    (inbox, important, other, routed)
}

pub fn unread_counts(
    conn: &Connection,
    account_id: Option<i64>,
    splits: &[SplitRule],
    labels: &[Label],
) -> Result<UnreadCounts> {
    let groups = inbox_tab_groups(conn, account_id, true)?;
    let (inbox, important, other, routed) = fold_tab_groups(&groups);

    let mut splits_map = HashMap::new();
    // A split can opt out of the unread filter so its badge shows how much
    // the tab holds even once everything in it has been read. Those need a
    // second grouped scan without the unread clause; every other tab, and
    // every split by default, still badges unread only.
    let any_count_all = splits.iter().any(|sp| sp.count_all);
    let tab_totals = if any_count_all {
        routed_tab_totals(conn, account_id)?
    } else {
        HashMap::new()
    };
    for sp in splits {
        let tab = format!("split:{}", sp.id);
        let n = if sp.count_all {
            tab_totals.get(&tab).copied().unwrap_or(0)
        } else {
            routed.get(&tab).copied().unwrap_or(0)
        };
        splits_map.insert(sp.id.to_string(), n);
    }

    // Auto-category tabs read the single resolved tab and stay inbox-scoped
    // (same grouped scan). Manual labels are a cross-cutting filter shown
    // against View::All: one grouped query counts each label's threads with
    // visible mail, archived or snoozed included.
    let manual: Vec<i64> = labels.iter().filter(|l| !l.is_auto).map(|l| l.id).collect();
    let manual_counts = manual_label_counts(conn, account_id, &manual, true)?;
    let mut labels_map = HashMap::new();
    for l in labels {
        let n = if l.is_auto {
            routed.get(&format!("label:{}", l.id)).copied().unwrap_or(0)
        } else {
            manual_counts.get(&l.id).copied().unwrap_or(0)
        };
        labels_map.insert(l.id.to_string(), n);
    }

    let mut views = HashMap::new();
    views.insert(
        "starred".to_string(),
        badge_count(
            conn,
            account_id,
            true,
            &[
                super::threads::HAS_VISIBLE_STAR,
                super::threads::HAS_VISIBLE_MAIL,
            ],
        )?,
    );
    views.insert(
        "snoozed".to_string(),
        badge_count(
            conn,
            account_id,
            true,
            &["s.thread_id IS NOT NULL", super::threads::HAS_VISIBLE_MAIL],
        )?,
    );
    // Spam is never notified, so its badge is the only signal that mail landed there.
    views.insert("spam".to_string(), badge_count(conn, account_id, false, &[
        "t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id=m.folder_id WHERE m.is_read=0 AND f.role='spam')"
    ])?);
    // Drafts badge = number of threads with a draft, unread or not.
    views.insert(
        "drafts".to_string(),
        badge_count(
            conn,
            account_id,
            false,
            &[
                "t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id = m.folder_id
                          WHERE m.is_draft = 1 AND f.role = 'drafts')",
            ],
        )?,
    );

    Ok(UnreadCounts {
        inbox,
        important,
        other,
        splits: splits_map,
        labels: labels_map,
        views,
    })
}

/// How many conversations each inbox tab, and the inbox as a whole, holds,
/// read or not. Same tab membership as the badges in `unread_counts`, minus
/// the unread filter; queried while the "all" tab-count setting is on, and
/// for the "Run automations" confirmation.
pub fn tab_totals(
    conn: &Connection,
    account_id: Option<i64>,
    splits: &[SplitRule],
    labels: &[Label],
) -> Result<TabTotals> {
    let groups = inbox_tab_groups(conn, account_id, false)?;
    let (inbox, important, other, routed) = fold_tab_groups(&groups);

    let mut splits_map = HashMap::new();
    for sp in splits {
        let n = routed
            .get(&format!("split:{}", sp.id))
            .copied()
            .unwrap_or(0);
        splits_map.insert(sp.id.to_string(), n);
    }

    let manual: Vec<i64> = labels.iter().filter(|l| !l.is_auto).map(|l| l.id).collect();
    let manual_counts = manual_label_counts(conn, account_id, &manual, false)?;
    let mut labels_map = HashMap::new();
    for l in labels {
        let n = if l.is_auto {
            routed.get(&format!("label:{}", l.id)).copied().unwrap_or(0)
        } else {
            manual_counts.get(&l.id).copied().unwrap_or(0)
        };
        labels_map.insert(l.id.to_string(), n);
    }

    Ok(TabTotals {
        inbox,
        important,
        other,
        splits: splits_map,
        labels: labels_map,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SplitRuleQuery;
    use rusqlite::params;

    fn test_db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::db::migrations::run(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO accounts (id, email, provider, auth_kind, username,
             imap_host, imap_port, smtp_host, smtp_port, created_at)
             VALUES (1,'t@x.com','imap','password','t','h',993,'h',587,0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO folders (id, account_id, imap_name, role) VALUES (1,1,'INBOX','inbox')",
            [],
        )
        .unwrap();
        conn
    }

    fn seed_thread(conn: &Connection, id: i64, unread: i64, automated: bool) {
        conn.execute(
            "INSERT INTO threads (id, account_id, subject_norm, unread_count, last_message_at)
             VALUES (?1, 1, 'subj', ?2, 1000)",
            params![id, unread],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (thread_id, account_id, folder_id, uid, message_id, subject,
             from_addr, date, is_read, is_automated, is_draft, is_outgoing)
             VALUES (?1, 1, 1, ?1, 'mid-' || ?1, 'subj', 'a@b.c', 1000, ?2, ?3, 0, 0)",
            params![id, (unread == 0) as i64, automated as i64],
        )
        .unwrap();
    }

    fn append_incoming(conn: &Connection, thread_id: i64, date: i64, automated: bool) {
        conn.execute(
            "INSERT INTO messages (thread_id, account_id, folder_id, subject,
             from_addr, date, is_read, is_automated, is_draft, is_outgoing)
             VALUES (?1, 1, 1, 'follow-up', 'reply@b.c', ?2, 0, ?3, 0, 0)",
            params![thread_id, date, automated as i64],
        )
        .unwrap();
    }

    #[test]
    fn partitions_important_and_other() {
        let conn = test_db();
        seed_thread(&conn, 1, 1, false); // unread human
        seed_thread(&conn, 2, 1, true); // unread automated
        seed_thread(&conn, 3, 0, true); // read automated

        let c = unread_counts(&conn, None, &[], &[]).unwrap();
        assert_eq!(c.inbox, 2);
        assert_eq!(c.important, 1);
        assert_eq!(c.other, 1);
        assert_eq!(c.views["starred"], 0);
        assert_eq!(c.views["spam"], 0);

        // account filter that matches nothing
        let none = unread_counts(&conn, Some(99), &[], &[]).unwrap();
        assert_eq!(none.inbox, 0);
    }

    #[test]
    fn mixed_threads_are_counted_by_the_newest_incoming_message() {
        let conn = test_db();
        seed_thread(&conn, 1, 1, false);
        append_incoming(&conn, 1, 2000, true);
        seed_thread(&conn, 2, 1, true);
        append_incoming(&conn, 2, 2000, false);

        let c = unread_counts(&conn, None, &[], &[]).unwrap();
        assert_eq!(c.inbox, 2);
        assert_eq!(c.important, 1, "latest human reply belongs in Important");
        assert_eq!(c.other, 1, "latest automated reply belongs in Other");
    }

    #[test]
    fn mixed_thread_badges_only_count_unread_in_their_scope() {
        let conn = test_db();
        conn.execute_batch("INSERT INTO folders(id,account_id,imap_name,role) VALUES (2,1,'Trash','trash'),(3,1,'Spam','spam');").unwrap();
        seed_thread(&conn, 1, 1, false);
        conn.execute("UPDATE messages SET folder_id=2 WHERE thread_id=1", [])
            .unwrap();
        append_incoming(&conn, 1, 2000, false);
        conn.execute(
            "UPDATE messages SET is_read=1,is_starred=1 WHERE folder_id=1",
            [],
        )
        .unwrap();
        let c = unread_counts(&conn, None, &[], &[]).unwrap();
        assert_eq!(c.inbox, 0, "unread trash must not badge read inbox mail");
        assert_eq!(c.views["starred"], 0);
        conn.execute("UPDATE messages SET folder_id=3 WHERE folder_id=2", [])
            .unwrap();
        let c = unread_counts(&conn, None, &[], &[]).unwrap();
        assert_eq!(c.views["spam"], 1);
        assert_eq!(c.inbox, 0);
        conn.execute(
            "UPDATE messages SET is_read=CASE WHEN folder_id=3 THEN 1 ELSE 0 END",
            [],
        )
        .unwrap();
        let c = unread_counts(&conn, None, &[], &[]).unwrap();
        assert_eq!(c.views["spam"], 0, "unread inbox must not badge read spam");
        assert_eq!(c.inbox, 1);
        assert_eq!(c.views["starred"], 1);
    }

    #[test]
    fn counts_unread_spam() {
        let conn = test_db();
        conn.execute(
            "INSERT INTO folders (id, account_id, imap_name, role) VALUES (2,1,'Spam','spam')",
            [],
        )
        .unwrap();
        seed_thread(&conn, 1, 1, false);
        seed_thread(&conn, 2, 1, false);
        seed_thread(&conn, 3, 0, false);
        conn.execute(
            "UPDATE messages SET folder_id = 2 WHERE thread_id IN (2, 3)",
            [],
        )
        .unwrap();

        let c = unread_counts(&conn, None, &[], &[]).unwrap();
        assert_eq!(c.views["spam"], 1);
        assert_eq!(c.inbox, 1);
    }

    #[test]
    fn split_and_label_maps() {
        let conn = test_db();
        seed_thread(&conn, 1, 1, false);
        conn.execute(
            "INSERT INTO labels (id, name, color, keyword, position) VALUES (5,'L','#fff','KwL',0)",
            [],
        )
        .unwrap();
        let msg_id: i64 = conn
            .query_row("SELECT id FROM messages WHERE thread_id = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        conn.execute(
            "INSERT INTO message_labels (message_id, label_id) VALUES (?1, 5)",
            params![msg_id],
        )
        .unwrap();
        // The custom-split count now reads the resolved tab, so route thread 1
        // into split:7 (the resolver does this at sync time).
        conn.execute("UPDATE threads SET routed_tab = 'split:7' WHERE id = 1", [])
            .unwrap();

        let split = SplitRule {
            id: 7,
            name: "s".into(),
            position: 0,
            query: SplitRuleQuery {
                senders: Some(vec!["a@b.c".into()]),
                ..Default::default()
            },
            condition: None,
            target: None,
            ai: None,
            count_all: false,
        };
        let label = Label {
            id: 5,
            name: "L".into(),
            color: "#fff".into(),
            keyword: "KwL".into(),
            position: 0,
            is_auto: false,
        };

        let c = unread_counts(&conn, Some(1), &[split], &[label]).unwrap();
        assert_eq!(c.splits["7"], 1);
        assert_eq!(c.labels["5"], 1);
    }

    #[test]
    fn count_all_split_badges_read_conversations_too() {
        let conn = test_db();
        seed_thread(&conn, 1, 1, false); // unread
        seed_thread(&conn, 2, 0, false); // read
        conn.execute(
            "UPDATE threads SET routed_tab = 'split:7' WHERE id IN (1, 2)",
            [],
        )
        .unwrap();

        let mut split = SplitRule {
            id: 7,
            name: "s".into(),
            position: 0,
            query: SplitRuleQuery::default(),
            condition: None,
            target: None,
            ai: None,
            count_all: false,
        };

        let unread_only = unread_counts(&conn, None, std::slice::from_ref(&split), &[]).unwrap();
        assert_eq!(unread_only.splits["7"], 1, "default stays unread-only");

        split.count_all = true;
        let all = unread_counts(&conn, None, std::slice::from_ref(&split), &[]).unwrap();
        assert_eq!(all.splits["7"], 2, "count_all includes the read thread");

        // The opt-in is per split: the shared inbox/Important/Other badges are
        // untouched by it.
        assert_eq!(all.inbox, unread_only.inbox);
        assert_eq!(all.important, unread_only.important);
    }

    #[test]
    fn tab_totals_count_read_and_unread_per_tab() {
        let conn = test_db();
        seed_thread(&conn, 1, 1, false); // unread human -> Important
        seed_thread(&conn, 2, 0, false); // read human -> Important
        seed_thread(&conn, 3, 0, true); // read automated -> Other
        seed_thread(&conn, 4, 0, false); // read, routed to split 7
        seed_thread(&conn, 5, 1, true); // unread, routed to auto label 9
        conn.execute("UPDATE threads SET routed_tab = 'split:7' WHERE id = 4", [])
            .unwrap();
        conn.execute("UPDATE threads SET routed_tab = 'label:9' WHERE id = 5", [])
            .unwrap();
        // Snoozed mail is out of the inbox, so no tab holds it.
        seed_thread(&conn, 6, 0, false);
        conn.execute(
            "INSERT INTO snoozes (thread_id, account_id, wake_at) VALUES (6, 1, 9999999999999)",
            [],
        )
        .unwrap();

        let split = SplitRule {
            id: 7,
            name: "s".into(),
            position: 0,
            query: SplitRuleQuery::default(),
            condition: None,
            target: None,
            ai: None,
            count_all: false,
        };
        let label = Label {
            id: 9,
            name: "News".into(),
            color: "#fff".into(),
            keyword: "KwNews".into(),
            position: 0,
            is_auto: true,
        };

        let t = tab_totals(&conn, None, &[split.clone()], &[label.clone()]).unwrap();
        assert_eq!(t.inbox, 5, "every tab's conversations, not the snoozed one");
        assert_eq!(t.important, 2, "read and unread Important mail");
        assert_eq!(t.other, 1);
        assert_eq!(t.splits["7"], 1);
        assert_eq!(t.labels["9"], 1);

        let none = tab_totals(&conn, Some(99), &[split], &[label]).unwrap();
        assert_eq!(none.inbox, 0);
        assert_eq!(none.important, 0);
        assert_eq!(none.splits["7"], 0);
    }

    /// Attach `label_id` to one message of each thread and register the label.
    fn label_threads(conn: &Connection, label_id: i64, is_auto: bool, thread_ids: &[i64]) {
        conn.execute(
            "INSERT INTO labels (id, name, color, keyword, position, is_auto)
             VALUES (?1, 'L' || ?1, '#fff', 'Kw', 0, ?2)",
            params![label_id, is_auto as i64],
        )
        .unwrap();
        for tid in thread_ids {
            let msg_id: i64 = conn
                .query_row(
                    "SELECT id FROM messages WHERE thread_id = ?1 LIMIT 1",
                    params![tid],
                    |r| r.get(0),
                )
                .unwrap();
            conn.execute(
                "INSERT INTO message_labels (message_id, label_id) VALUES (?1, ?2)",
                params![msg_id, label_id],
            )
            .unwrap();
        }
    }

    fn label(id: i64, is_auto: bool) -> Label {
        Label {
            id,
            name: "L".into(),
            color: "#fff".into(),
            keyword: "Kw".into(),
            position: 0,
            is_auto,
        }
    }

    #[test]
    fn manual_label_badge_matches_the_all_view_scope() {
        let conn = test_db();
        conn.execute_batch(
            "INSERT INTO folders (id, account_id, imap_name, role) VALUES
             (2,1,'Archive','archive'),(3,1,'Trash','trash');",
        )
        .unwrap();
        seed_thread(&conn, 1, 1, false); // unread, in the inbox
        seed_thread(&conn, 2, 1, false); // unread, archived
        seed_thread(&conn, 3, 1, false); // unread, snoozed
        seed_thread(&conn, 4, 1, false); // unread, only in trash
        conn.execute("UPDATE messages SET folder_id = 2 WHERE thread_id = 2", [])
            .unwrap();
        conn.execute(
            "INSERT INTO snoozes (thread_id, account_id, wake_at) VALUES (3, 1, 9999999999999)",
            [],
        )
        .unwrap();
        conn.execute("UPDATE messages SET folder_id = 3 WHERE thread_id = 4", [])
            .unwrap();
        // Threads 1 and 2 also route to auto label 9's tab.
        conn.execute(
            "UPDATE threads SET routed_tab = 'label:9' WHERE id IN (1, 2)",
            [],
        )
        .unwrap();

        label_threads(&conn, 5, false, &[1, 2, 3, 4]);
        let manual = label(5, false);
        let auto = label(9, true);
        label_threads(&conn, 9, true, &[]);

        let c = unread_counts(&conn, None, &[], &[manual.clone(), auto.clone()]).unwrap();
        assert_eq!(
            c.labels["5"], 3,
            "inbox + archived + snoozed count; trash-only mail stays hidden"
        );
        assert_eq!(
            c.labels["9"], 1,
            "auto labels keep the inbox scope: only the inbox thread counts"
        );

        let t = tab_totals(&conn, None, &[], &[manual, auto]).unwrap();
        assert_eq!(t.labels["5"], 3);
        assert_eq!(t.labels["9"], 1);
    }

    // ---- Reference implementation + differential test ----------------------
    //
    // The pre-optimisation implementations, kept verbatim as the equivalence
    // oracle: one COUNT(*) per badge, prepared per call.

    fn unread_counts_reference(
        conn: &Connection,
        account_id: Option<i64>,
        splits: &[SplitRule],
        labels: &[Label],
    ) -> Result<UnreadCounts> {
        let inbox = Q::unread(account_id).inbox().run(conn)?;
        let important = Q::unread(account_id).inbox().bucket(false).run(conn)?;
        let other = Q::unread(account_id).inbox().bucket(true).run(conn)?;

        let mut splits_map = HashMap::new();
        for sp in splits {
            let base = if sp.count_all {
                Q::any(account_id)
            } else {
                Q::unread(account_id)
            };
            let n = base.inbox().routed_split(sp.id).run(conn)?;
            splits_map.insert(sp.id.to_string(), n);
        }

        let mut labels_map = HashMap::new();
        for l in labels {
            let n = if l.is_auto {
                Q::unread(account_id).inbox().routed_label(l.id).run(conn)?
            } else {
                Q::unread(account_id)
                    .clause(crate::db::repo::threads::HAS_VISIBLE_MAIL)
                    .label(l.id)
                    .run(conn)?
            };
            labels_map.insert(l.id.to_string(), n);
        }

        let mut views = HashMap::new();
        views.insert(
            "starred".to_string(),
            Q::unread(account_id)
                .clause(crate::db::repo::threads::HAS_VISIBLE_STAR)
                .clause(crate::db::repo::threads::HAS_VISIBLE_MAIL)
                .run(conn)?,
        );
        views.insert(
            "snoozed".to_string(),
            Q::unread(account_id)
                .clause("s.thread_id IS NOT NULL")
                .clause(crate::db::repo::threads::HAS_VISIBLE_MAIL)
                .run(conn)?,
        );
        views.insert("spam".to_string(), Q::any(account_id).clause(
            "t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id=m.folder_id WHERE m.is_read=0 AND f.role='spam')"
        ).run(conn)?);
        views.insert(
            "drafts".to_string(),
            Q::any(account_id)
                .clause(
                    "t.id IN (SELECT m.thread_id FROM visible_messages m JOIN folders f ON f.id = m.folder_id
                              WHERE m.is_draft = 1 AND f.role = 'drafts')",
                )
                .run(conn)?,
        );

        Ok(UnreadCounts {
            inbox,
            important,
            other,
            splits: splits_map,
            labels: labels_map,
            views,
        })
    }

    fn tab_totals_reference(
        conn: &Connection,
        account_id: Option<i64>,
        splits: &[SplitRule],
        labels: &[Label],
    ) -> Result<TabTotals> {
        let inbox = Q::any(account_id).inbox().run(conn)?;
        let important = Q::any(account_id).inbox().bucket(false).run(conn)?;
        let other = Q::any(account_id).inbox().bucket(true).run(conn)?;

        let mut splits_map = HashMap::new();
        for sp in splits {
            let n = Q::any(account_id).inbox().routed_split(sp.id).run(conn)?;
            splits_map.insert(sp.id.to_string(), n);
        }

        let mut labels_map = HashMap::new();
        for l in labels {
            let n = if l.is_auto {
                Q::any(account_id).inbox().routed_label(l.id).run(conn)?
            } else {
                Q::any(account_id)
                    .clause(crate::db::repo::threads::HAS_VISIBLE_MAIL)
                    .label(l.id)
                    .run(conn)?
            };
            labels_map.insert(l.id.to_string(), n);
        }

        Ok(TabTotals {
            inbox,
            important,
            other,
            splits: splits_map,
            labels: labels_map,
        })
    }

    /// Deterministic xorshift64 so the varied database is reproducible.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn chance(&mut self, pct: u64) -> bool {
            self.next() % 100 < pct
        }
        fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
            &xs[(self.next() as usize) % xs.len()]
        }
    }

    fn split(id: i64, count_all: bool) -> SplitRule {
        SplitRule {
            id,
            name: "s".into(),
            position: 0,
            query: SplitRuleQuery::default(),
            condition: None,
            target: None,
            ai: None,
            count_all,
        }
    }

    /// Two accounts, five folders each, several hundred threads with mixed
    /// visibility/routing/read state; manual + auto labels and splits.
    fn varied_db(threads_per_account: i64, seed: u64) -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        crate::db::migrations::run(&mut conn).unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (id, email, provider, auth_kind, username,
             imap_host, imap_port, smtp_host, smtp_port, created_at) VALUES
             (1,'a@x.com','imap','password','a','h',993,'h',587,0),
             (2,'b@x.com','imap','password','b','h',993,'h',587,0);
             INSERT INTO folders (id, account_id, imap_name, role) VALUES
             (1,1,'INBOX','inbox'),(2,1,'Archive','archive'),(3,1,'Trash','trash'),
             (4,1,'Spam','spam'),(5,1,'Drafts','drafts'),
             (6,2,'INBOX','inbox'),(7,2,'Archive','archive'),(8,2,'Trash','trash'),
             (9,2,'Spam','spam'),(10,2,'Drafts','drafts');
             INSERT INTO labels (id, name, color, keyword, position, is_auto) VALUES
             (5,'L5','#fff','K5',0,0),(6,'L6','#fff','K6',1,0),
             (9,'A9','#fff','K9',2,1),(10,'A10','#fff','K10',3,1),
             (12,'A12','#fff','K12',4,1),(13,'L13','#fff','K13',5,0);",
        )
        .unwrap();

        let mut rng = Rng(seed.max(1));
        let routed = [
            None,
            None,
            None,
            None,
            Some("pending"),
            Some("important"),
            Some("other"),
            Some("split:7"),
            Some("split:7"),
            Some("split:8"),
            Some("label:9"),
            Some("label:10"),
            Some("split:99"), // routed to a tab that no longer exists
        ];
        // folder offsets per account: inbox, archive, trash, spam, drafts
        let folder_weights = [0usize, 0, 0, 0, 1, 1, 2, 3, 4];

        let tx = conn.transaction().unwrap();
        let mut ins_thread = tx
            .prepare(
                "INSERT INTO threads (account_id, subject_norm, routed_tab, last_message_at)
                      VALUES (?1, 'subj', ?2, 0)",
            )
            .unwrap();
        let mut ins_msg = tx
            .prepare("INSERT INTO messages (thread_id, account_id, folder_id, uid, message_id,
                     subject, from_addr, date, is_read, is_automated, is_draft, is_outgoing, is_starred)
                     VALUES (?1,?2,?3,?4,'mid-' || ?4,'s','a@b.c',?5,?6,?7,?8,?9,?10)")
            .unwrap();
        let mut ins_label = tx
            .prepare("INSERT INTO message_labels (message_id, label_id) VALUES (?1,?2)")
            .unwrap();
        let mut ins_snooze = tx
            .prepare(
                "INSERT INTO snoozes (thread_id, account_id, wake_at) VALUES (?1,?2,9999999999999)",
            )
            .unwrap();

        let mut date = 1_000_000i64;
        for account in [1i64, 2] {
            for _ in 0..threads_per_account {
                let tab: Option<&str> = *rng.pick(&routed);
                ins_thread.execute(params![account, tab]).unwrap();
                let tid = tx.last_insert_rowid();
                // Every thread gets 1-4 messages; a few threads land entirely
                // in trash/spam so they have no visible mail.
                let all_junk = rng.chance(8);
                let n = 1 + (rng.next() % 4) as usize;
                for i in 0..n {
                    let folder_off = if all_junk {
                        *rng.pick(&[2usize, 3])
                    } else {
                        *rng.pick(&folder_weights)
                    };
                    let folder_id = (account - 1) * 5 + 1 + folder_off as i64;
                    let is_draft = folder_off == 4 && rng.chance(80);
                    let is_outgoing = !is_draft && rng.chance(15);
                    date += 1 + (rng.next() % 60_000) as i64;
                    ins_msg
                        .execute(params![
                            tid,
                            account,
                            folder_id,
                            tid * 10 + i as i64,
                            date,
                            rng.chance(50) as i64,
                            rng.chance(30) as i64,
                            is_draft as i64,
                            is_outgoing as i64,
                            rng.chance(15) as i64,
                        ])
                        .unwrap();
                    let mid = tx.last_insert_rowid();
                    for label_id in [5i64, 6] {
                        if rng.chance(12) {
                            ins_label.execute(params![mid, label_id]).unwrap();
                        }
                    }
                }
                if rng.chance(15) {
                    ins_snooze.execute(params![tid, account]).unwrap();
                }
            }
        }
        drop(ins_thread);
        drop(ins_msg);
        drop(ins_label);
        drop(ins_snooze);
        tx.commit().unwrap();
        conn
    }

    fn fixture_tabs() -> (Vec<SplitRule>, Vec<Label>) {
        (
            vec![split(7, false), split(8, true), split(11, true)],
            vec![
                label(5, false),
                label(6, false),
                label(9, true),
                label(10, true),
                label(12, true),  // registered but nothing routes to it
                label(13, false), // manual, attached to nothing
            ],
        )
    }

    fn assert_counts_eq(new: &UnreadCounts, reference: &UnreadCounts, scope: &str) {
        assert_eq!(new.inbox, reference.inbox, "{scope}: inbox");
        assert_eq!(new.important, reference.important, "{scope}: important");
        assert_eq!(new.other, reference.other, "{scope}: other");
        assert_eq!(new.splits, reference.splits, "{scope}: splits");
        assert_eq!(new.labels, reference.labels, "{scope}: labels");
        assert_eq!(new.views, reference.views, "{scope}: views");
    }

    #[test]
    fn grouped_counts_match_the_reference_on_a_varied_mailbox() {
        let conn = varied_db(300, 0x9e3779b97f4a7c15);
        let (splits, labels) = fixture_tabs();
        for scope in [None, Some(1), Some(2), Some(999)] {
            let new = unread_counts(&conn, scope, &splits, &labels).unwrap();
            let reference = unread_counts_reference(&conn, scope, &splits, &labels).unwrap();
            assert_counts_eq(&new, &reference, &format!("unread/{scope:?}"));

            let new_t = tab_totals(&conn, scope, &splits, &labels).unwrap();
            let ref_t = tab_totals_reference(&conn, scope, &splits, &labels).unwrap();
            assert_eq!(new_t.inbox, ref_t.inbox, "totals/{scope:?}: inbox");
            assert_eq!(
                new_t.important, ref_t.important,
                "totals/{scope:?}: important"
            );
            assert_eq!(new_t.other, ref_t.other, "totals/{scope:?}: other");
            assert_eq!(new_t.splits, ref_t.splits, "totals/{scope:?}: splits");
            assert_eq!(new_t.labels, ref_t.labels, "totals/{scope:?}: labels");
        }
    }

    /// Before/after timings on a large mailbox plus the query plan of the
    /// grouped scan. Run: cargo test -p comail-core counts_bench -- --ignored --nocapture
    #[test]
    #[ignore = "benchmark; run on demand"]
    fn counts_bench() {
        let seed_start = std::time::Instant::now();
        let conn = varied_db(2_500, 42); // ~12k messages over two accounts
        eprintln!("seeded in {seed_start:?}");
        let (splits, labels) = fixture_tabs();
        for (scoped, unread) in [(true, true), (false, false)] {
            let sql = inbox_tab_groups_sql(scoped, unread);
            eprintln!("--- EXPLAIN QUERY PLAN (scoped={scoped} unread={unread})");
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let params: Vec<i64> = if scoped { vec![1] } else { vec![] };
            let mut rows = stmt.query(rusqlite::params_from_iter(params)).unwrap();
            while let Some(r) = rows.next().unwrap() {
                let detail: String = r.get(3).unwrap();
                eprintln!("    {detail}");
            }
        }
        for _ in 0..2 {
            unread_counts(&conn, None, &splits, &labels).unwrap();
            unread_counts_reference(&conn, None, &splits, &labels).unwrap();
        }
        let time = |f: &dyn Fn() -> Result<UnreadCounts>| {
            let t0 = std::time::Instant::now();
            for _ in 0..3 {
                f().unwrap();
            }
            t0.elapsed() / 3
        };
        let new_t = time(&|| unread_counts(&conn, None, &splits, &labels));
        let ref_t = time(&|| unread_counts_reference(&conn, None, &splits, &labels));
        let new_scoped = time(&|| unread_counts(&conn, Some(1), &splits, &labels));
        let ref_scoped = time(&|| unread_counts_reference(&conn, Some(1), &splits, &labels));
        eprintln!("unread_counts  all-accounts: new {new_t:?}  reference {ref_t:?}");
        eprintln!("unread_counts  account=1   : new {new_scoped:?}  reference {ref_scoped:?}");
        let new_tt = {
            let t0 = std::time::Instant::now();
            for _ in 0..5 {
                tab_totals(&conn, None, &splits, &labels).unwrap();
            }
            t0.elapsed() / 5
        };
        let ref_tt = {
            let t0 = std::time::Instant::now();
            for _ in 0..5 {
                tab_totals_reference(&conn, None, &splits, &labels).unwrap();
            }
            t0.elapsed() / 5
        };
        eprintln!("tab_totals     all-accounts: new {new_tt:?}  reference {ref_tt:?}");
    }
}
