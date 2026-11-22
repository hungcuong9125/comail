use comail_core::Core;
use comail_core::config::Paths;
use comail_core::models::{
    ActionKind, Address, DraftAttachmentIn, PerformActionArgs, QueueSendArgs, SaveDraftArgs, View,
    now_ms,
};

async fn setup() -> (tempfile::TempDir, Core) {
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::for_tests(tmp.path());
    let core = Core::start(paths).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                 VALUES (1,'me@example.com','imap','password','me','127.0.0.1',1,'127.0.0.1',1,0);
                 INSERT INTO folders (id,account_id,imap_name,role) VALUES
                   (1,1,'Drafts','drafts'),
                   (2,1,'Archive','archive'),
                   (3,1,'Trash','trash');",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    (tmp, core)
}

/// "The user picked this file in the dialog": mint an approval token for
/// `path` as `pick_draft_attachments` does once the dialog returns.
async fn token_for(core: &Core, path: &std::path::Path) -> DraftAttachmentIn {
    let approved = core
        .approve_attachment_sources(vec![path.to_path_buf()], None)
        .unwrap();
    assert_eq!(approved.len(), 1, "approve skipped {path:?}");
    DraftAttachmentIn::Token {
        token: approved[0].token.clone(),
    }
}

fn args(attachment: Option<DraftAttachmentIn>) -> SaveDraftArgs {
    SaveDraftArgs {
        draft_id: None,
        account_id: 1,
        to: vec![Address {
            name: Some("To".into()),
            email: "to@example.com".into(),
        }],
        cc: vec![Address {
            name: None,
            email: "cc@example.com".into(),
        }],
        bcc: vec![Address {
            name: None,
            email: "bcc@example.com".into(),
        }],
        subject: "Half-written".into(),
        body_text: "Still working".into(),
        body_html: Some("<p>Still <strong>working</strong></p>".into()),
        mode: "new".into(),
        in_reply_to_message_id: None,
        attachments: attachment.into_iter().collect(),
        composer_nonce: None,
    }
}

#[tokio::test]
async fn saved_draft_can_be_reloaded_without_losing_editable_fields() {
    let (tmp, core) = setup().await;
    let source = tmp.path().join("notes.txt");
    std::fs::write(&source, "notes").unwrap();
    let draft_id = core
        .save_draft(args(Some(token_for(&core, &source).await)))
        .await
        .unwrap()
        .draft_id;

    let loaded = core.get_draft(draft_id).await.unwrap();
    assert_eq!(loaded.draft_id, Some(draft_id));
    assert_eq!(loaded.to[0].email, "to@example.com");
    assert_eq!(loaded.cc[0].email, "cc@example.com");
    assert_eq!(loaded.bcc[0].email, "bcc@example.com");
    assert_eq!(loaded.body_text, "Still working");
    assert_eq!(
        loaded.body_html.as_deref(),
        Some("<p>Still <strong>working</strong></p>")
    );
    assert_eq!(loaded.attachments.len(), 1);
    // Reloaded attachments are `Staged` echoes the composer returns verbatim.
    let DraftAttachmentIn::Staged {
        file_path,
        filename,
        ..
    } = &loaded.attachments[0]
    else {
        panic!("get_draft must return Staged attachment references");
    };
    assert_eq!(filename, "notes.txt");
    assert_ne!(file_path.as_str(), source.to_string_lossy());
}

#[tokio::test]
async fn archive_and_trash_remove_local_drafts_from_the_drafts_view() {
    let (_tmp, core) = setup().await;
    let archived_id = core.save_draft(args(None)).await.unwrap().draft_id;
    let thread_id = core
        .db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT thread_id FROM messages WHERE id = ?1",
                [archived_id],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();

    core.perform_action(PerformActionArgs {
        kind: ActionKind::Archive,
        thread_ids: vec![thread_id],
        params: None,
    })
    .await
    .unwrap();
    assert!(
        core.list_threads(View::Drafts, None, None, None, None, None, 10)
            .await
            .unwrap()
            .threads
            .is_empty()
    );
    assert_eq!(
        core.list_threads(View::Done, None, None, None, None, None, 10)
            .await
            .unwrap()
            .threads
            .len(),
        1
    );

    let trashed_id = core.save_draft(args(None)).await.unwrap().draft_id;
    let trashed_thread = core
        .db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT thread_id FROM messages WHERE id = ?1",
                [trashed_id],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();
    core.perform_action(PerformActionArgs {
        kind: ActionKind::Trash,
        thread_ids: vec![trashed_thread],
        params: None,
    })
    .await
    .unwrap();
    assert!(
        core.list_threads(View::Drafts, None, None, None, None, None, 10)
            .await
            .unwrap()
            .threads
            .is_empty()
    );
    assert_eq!(
        core.list_threads(View::Trash, None, None, None, None, None, 10)
            .await
            .unwrap()
            .threads
            .len(),
        1
    );
}

#[tokio::test]
async fn deleting_a_remote_draft_queues_trash_instead_of_allowing_resurrection() {
    let (_tmp, core) = setup().await;
    let draft_id = core.save_draft(args(None)).await.unwrap().draft_id;
    core.db
        .write(move |conn| {
            conn.execute("UPDATE messages SET uid = 42 WHERE id = ?1", [draft_id])?;
            Ok(())
        })
        .await
        .unwrap();

    core.delete_draft(draft_id).await.unwrap();
    let (role, action, source_guard): (String, String, bool) = core
        .db
        .read(move |conn| {
            let role = conn.query_row(
                "SELECT f.role FROM messages m JOIN folders f ON f.id = m.folder_id
                 WHERE m.id = ?1",
                [draft_id],
                |row| row.get(0),
            )?;
            let action = conn.query_row(
                "SELECT kind FROM pending_actions WHERE message_id = ?1 ORDER BY id DESC LIMIT 1",
                [draft_id],
                |row| row.get(0),
            )?;
            let source_guard =
                comail_core::db::repo::actions::has_active_move_from(conn, draft_id, 1)?;
            Ok((role, action, source_guard))
        })
        .await
        .unwrap();
    assert_eq!(role, "trash");
    assert_eq!(action, "trash");
    assert!(source_guard, "sync must not relink the old Drafts copy");
    assert!(
        core.list_threads(View::Drafts, None, None, None, None, None, 10)
            .await
            .unwrap()
            .threads
            .is_empty()
    );
}

// -----------------------------------------------------------------------
// is_draft-gated update: `save_draft` must refuse non-draft message ids.
// The id of a sent or inbound message used to get its body, snippet and
// attachment rows overwritten; the gated UPDATE now fails the save.
// -----------------------------------------------------------------------

fn update_args(draft_id: i64) -> SaveDraftArgs {
    SaveDraftArgs {
        draft_id: Some(draft_id),
        ..args(None)
    }
}

async fn seed_real_message(core: &Core, id: i64, outgoing: bool) {
    core.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO messages
                   (id,account_id,thread_id,folder_id,uid,message_id,subject,date,is_read,
                    is_draft,is_outgoing,has_attachments,snippet,body_state)
                 VALUES (?1,1,NULL,2,?1,?2,'keep me',1000,1,0,?3,0,'orig snippet','cached')",
                rusqlite::params![id, format!("<m{id}@x>"), outgoing as i64],
            )?;
            conn.execute(
                "INSERT INTO message_bodies (message_id,text_body,html_body)
                 VALUES (?1,'orig text','<p>orig</p>')",
                [id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
}

async fn assert_message_untouched(core: &Core, id: i64) {
    core.db
        .read(move |conn| {
            let (subject, snippet, has_atts, body_state): (String, String, i64, String) = conn
                .query_row(
                    "SELECT subject, snippet, has_attachments, body_state FROM messages WHERE id = ?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
            assert_eq!(subject, "keep me");
            assert_eq!(snippet, "orig snippet");
            assert_eq!(has_atts, 0);
            assert_eq!(body_state, "cached");
            let (text, html): (String, String) = conn.query_row(
                "SELECT text_body, html_body FROM message_bodies WHERE message_id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            assert_eq!(text, "orig text");
            assert_eq!(html, "<p>orig</p>");
            let att_rows: i64 = conn.query_row(
                "SELECT COUNT(*) FROM draft_attachments WHERE draft_id = ?1",
                [id],
                |row| row.get(0),
            )?;
            assert_eq!(att_rows, 0);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn save_draft_refuses_sent_message_id() {
    let (_tmp, core) = setup().await;
    let sent_id = 910_i64;
    seed_real_message(&core, sent_id, true).await;

    let err = core.save_draft(update_args(sent_id)).await.unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::NotFound(_)),
        "expected NotFound, got {err:?}"
    );
    assert_message_untouched(&core, sent_id).await;
}

#[tokio::test]
async fn save_draft_refuses_inbound_message_id() {
    let (_tmp, core) = setup().await;
    let inbound_id = 911_i64;
    seed_real_message(&core, inbound_id, false).await;

    let err = core.save_draft(update_args(inbound_id)).await.unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::NotFound(_)),
        "expected NotFound, got {err:?}"
    );
    assert_message_untouched(&core, inbound_id).await;
}

#[tokio::test]
async fn rejected_save_removes_freshly_staged_attachment() {
    let (tmp, core) = setup().await;
    let sent_id = 912_i64;
    seed_real_message(&core, sent_id, true).await;

    let src = tmp.path().join("attach.bin");
    std::fs::write(&src, b"payload").unwrap();
    let mut a = update_args(sent_id);
    a.attachments.push(token_for(&core, &src).await);
    let err = core.save_draft(a).await.unwrap_err();
    assert!(matches!(err, comail_core::error::CoreError::NotFound(_)));

    // The staged copy was made before the transaction rejected the save; it
    // must be gone now, along with its per-file subdirectory.
    let root = comail_core::config::Paths::for_tests(tmp.path()).draft_attachments_dir();
    let leftovers: Vec<_> = std::fs::read_dir(&root)
        .map(|rd| rd.flatten().collect())
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "staged files left behind: {leftovers:?}"
    );
    assert_message_untouched(&core, sent_id).await;
}

// -----------------------------------------------------------------------
// delete_draft vs queued sends: a pending send must not outlive the
// delete (it would dispatch without attachments); a send already in
// flight refuses the delete instead of racing it.
// -----------------------------------------------------------------------

#[tokio::test]
async fn delete_draft_cancels_its_pending_send() {
    let (_tmp, core) = setup().await;
    let draft_id = core.save_draft(args(None)).await.unwrap().draft_id;
    let send_at = now_ms() + 3_600_000; // far future: never dispatches here
    let result = core
        .queue_send(QueueSendArgs {
            draft_id,
            send_at: Some(send_at),
        })
        .await
        .unwrap();

    core.delete_draft(draft_id).await.unwrap();

    let state: String = core
        .db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT state FROM pending_actions WHERE id = ?1",
                [result.action_id],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(
        state, "cancelled",
        "pending send must not outlive the draft"
    );
}

#[tokio::test]
async fn delete_draft_refuses_while_its_send_is_in_flight() {
    let (_tmp, core) = setup().await;
    let draft_id = core.save_draft(args(None)).await.unwrap().draft_id;
    let result = core
        .queue_send(QueueSendArgs {
            draft_id,
            send_at: Some(now_ms() + 3_600_000),
        })
        .await
        .unwrap();
    core.db
        .write(move |conn| {
            conn.execute(
                "UPDATE pending_actions SET state = 'inflight' WHERE id = ?1",
                [result.action_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let err = core.delete_draft(draft_id).await.unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "expected ActionRejected, got {err:?}"
    );
    // The draft and the in-flight action are both untouched.
    let (is_draft, state): (i64, String) = core
        .db
        .read(move |conn| {
            let is_draft = conn.query_row(
                "SELECT is_draft FROM messages WHERE id = ?1",
                [draft_id],
                |r| r.get(0),
            )?;
            let state = conn.query_row(
                "SELECT state FROM pending_actions WHERE id = ?1",
                [result.action_id],
                |r| r.get(0),
            )?;
            Ok((is_draft, state))
        })
        .await
        .unwrap();
    assert_eq!(is_draft, 1);
    assert_eq!(state, "inflight");
}

#[tokio::test]
async fn deleting_a_remote_draft_without_a_trash_folder_is_rejected_not_gone() {
    let (tmp, core) = setup().await;
    // A server draft with a staged attachment and a queued send: the rejected
    // delete must leave ALL of it - the row, the attachment rows and files,
    // and the pending send action - exactly as it was.
    let src = tmp.path().join("keep.bin");
    std::fs::write(&src, b"payload").unwrap();
    let draft_id = core
        .save_draft(args(Some(token_for(&core, &src).await)))
        .await
        .unwrap()
        .draft_id;
    let send = core
        .queue_send(QueueSendArgs {
            draft_id,
            send_at: Some(now_ms() + 3_600_000),
        })
        .await
        .unwrap();
    let staged_path: String = core
        .db
        .read(move |conn| {
            conn.query_row(
                "SELECT file_path FROM draft_attachments WHERE draft_id = ?1",
                [draft_id],
                |r| r.get(0),
            )
            .map_err(Into::into)
        })
        .await
        .unwrap();
    core.db
        .write(move |conn| {
            conn.execute("UPDATE messages SET uid = 42 WHERE id = ?1", [draft_id])?;
            conn.execute("DELETE FROM folders WHERE role = 'trash'", [])?;
            Ok(())
        })
        .await
        .unwrap();

    // The draft is still there; the delete cannot proceed - "delete
    // rejected", not "draft gone", so callers must not treat it as already
    // deleted.
    let err = core.delete_draft(draft_id).await.unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::DeleteRejected(_)),
        "expected DeleteRejected, got {err:?}"
    );
    let (is_draft, uid, att_rows, send_state): (i64, Option<i64>, i64, String) = core
        .db
        .read(move |conn| {
            let (is_draft, uid) = conn.query_row(
                "SELECT is_draft, uid FROM messages WHERE id = ?1",
                [draft_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
            )?;
            let att_rows = conn.query_row(
                "SELECT COUNT(*) FROM draft_attachments WHERE draft_id = ?1",
                [draft_id],
                |row| row.get(0),
            )?;
            let send_state = conn.query_row(
                "SELECT state FROM pending_actions WHERE id = ?1",
                [send.action_id],
                |row| row.get(0),
            )?;
            Ok((is_draft, uid, att_rows, send_state))
        })
        .await
        .unwrap();
    assert_eq!((is_draft, uid), (1, Some(42)), "draft must be untouched");
    assert_eq!(
        att_rows, 1,
        "attachment rows must survive a rejected delete"
    );
    assert_eq!(send_state, "pending", "queued send must not be cancelled");
    assert!(
        std::path::Path::new(&staged_path).exists(),
        "staged file must survive a rejected delete"
    );
}
