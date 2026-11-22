use super::*;

/// A re-queued send (crash between the post-send commit and the action
/// being marked done) must be a no-op: dispatching again would deliver a
/// duplicate without attachments.
#[test]
fn send_is_skipped_once_the_message_is_no_longer_a_draft() {
    let conn = crate::db::testutil::conn();
    crate::db::testutil::seed_account(&conn);
    let (_, msg) = crate::db::testutil::seed_message(&conn, "a@b.dev", "x", false);
    // Inbound message: not a draft, nothing to send.
    assert!(!send_still_needed(&conn, msg).unwrap());
    conn.execute("UPDATE messages SET is_draft = 1 WHERE id = ?1", [msg])
        .unwrap();
    assert!(send_still_needed(&conn, msg).unwrap());
    // The post-send commit flips this bit; a replayed action sees it.
    conn.execute("UPDATE messages SET is_draft = 0 WHERE id = ?1", [msg])
        .unwrap();
    assert!(!send_still_needed(&conn, msg).unwrap());
    // A draft deleted outright can never be sent either.
    conn.execute("DELETE FROM messages WHERE id = ?1", [msg])
        .unwrap();
    assert!(!send_still_needed(&conn, msg).unwrap());
}

/// `finalize_sent_draft` only runs after the server accepted the message.
/// When it does, the draft flips to sent and its meta + attachment rows go
/// atomically, returning the staged paths for post-commit file removal.
/// Any failure before that point leaves rows and files for the retry.
#[test]
fn finalize_sent_draft_flips_state_and_collects_staged_paths() {
    let mut conn = crate::db::testutil::conn();
    crate::db::testutil::seed_account(&conn);
    let (thread_id, draft_id) =
        crate::db::testutil::seed_message(&conn, "me@test.dev", "draft", false);
    conn.execute("UPDATE messages SET is_draft = 1 WHERE id = ?1", [draft_id])
        .unwrap();
    conn.execute(
        "INSERT INTO drafts_meta (message_id, mode, in_reply_to_message_id)
         VALUES (?1, 'new', NULL)",
        [draft_id],
    )
    .unwrap();
    for path in ["/staging/aa/one.txt", "/staging/bb/two.txt"] {
        conn.execute(
            "INSERT INTO draft_attachments (draft_id, file_path, filename, mime_type)
             VALUES (?1, ?2, 'x.txt', 'text/plain')",
            rusqlite::params![draft_id, path],
        )
        .unwrap();
    }
    let sent_to = vec![Address {
        name: None,
        email: "rcpt@b.dev".into(),
    }];
    let (tid, staged) =
        finalize_sent_draft(&mut conn, draft_id, "sent-mid@x", None, &sent_to, 1).unwrap();
    assert_eq!(tid, Some(thread_id));
    assert_eq!(staged.len(), 2);
    let is_draft: i64 = conn
        .query_row(
            "SELECT is_draft FROM messages WHERE id = ?1",
            [draft_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(is_draft, 0);
    let meta_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM drafts_meta WHERE message_id = ?1",
            [draft_id],
            |r| r.get(0),
        )
        .unwrap();
    let att_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM draft_attachments WHERE draft_id = ?1",
            [draft_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(meta_rows, 0, "drafts_meta must go with the sent flip");
    assert_eq!(att_rows, 0, "attachment rows must go with the sent flip");
    // A replayed action now observes "already sent".
    assert!(!send_still_needed(&conn, draft_id).unwrap());
}
