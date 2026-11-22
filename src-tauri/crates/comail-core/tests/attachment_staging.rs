//! Security regression tests for the draft-attachment staging boundary.
//!
//! `save_draft` once accepted an attachment `file_path` straight from the
//! frontend IPC, copied whatever it named into staging, and later mailed it -
//! an arbitrary local-file read/exfil primitive for any script in the
//! webview. Now a draft attachment can only be an approval token minted by a
//! trusted Rust path (the native file dialog, an OS drop observed in Rust,
//! or a forward source resolved via `prepare_forward_attachment`), a staged
//! path this same draft already owns, or - inside the same composer session -
//! a staged path a previous save produced (draft-recreated adoption). These
//! tests drive the real `save_draft` path end to
//! end; `approve_attachment_sources` stands in for "the dialog returned this
//! path" - the dialog call itself is the only line tests cannot drive.

use comail_core::Core;
use comail_core::config::Paths;
use comail_core::models::{DraftAttachmentIn, SaveDraftArgs, roles};

async fn stored_paths(core: &Core, draft_id: i64) -> Vec<String> {
    // Manual row loop so the test needn't name `rusqlite` (not a dev-dep); the
    // `?`s convert rusqlite errors into CoreError via the crate's From impl.
    core.db
        .read(move |conn| {
            let mut stmt =
                conn.prepare("SELECT file_path FROM draft_attachments WHERE draft_id = ?1")?;
            let mut rows = stmt.query([draft_id])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(row.get::<_, String>(0)?);
            }
            Ok(out)
        })
        .await
        .unwrap()
}

fn draft_args(account_id: i64, atts: Vec<DraftAttachmentIn>) -> SaveDraftArgs {
    SaveDraftArgs {
        draft_id: None,
        account_id,
        to: vec![],
        cc: vec![],
        bcc: vec![],
        subject: "hello".into(),
        body_text: "body".into(),
        body_html: None,
        mode: "new".into(),
        in_reply_to_message_id: None,
        attachments: atts,
        composer_nonce: None,
    }
}

/// "The dialog (or an approved internal source) returned this path": mint a
/// token for `path` exactly as `pick_draft_attachments` does after the native
/// dialog returns.
async fn token_for(core: &Core, path: &std::path::Path) -> DraftAttachmentIn {
    let approved = core
        .approve_attachment_sources(vec![path.to_path_buf()], None)
        .unwrap();
    assert_eq!(approved.len(), 1, "approve skipped {path:?}");
    DraftAttachmentIn::Token {
        token: approved[0].token.clone(),
    }
}

#[tokio::test]
async fn save_draft_stages_external_file_into_app_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);

    // A "secret" file living OUTSIDE the app data dir - what the user picked
    // through the trusted dialog path.
    let secret = tmp.path().join("secret.txt");
    std::fs::write(&secret, b"top secret bytes").unwrap();

    let core = Core::start(paths.clone()).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'me@example.com','imap','password','me','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts');",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    // Sanity: role constant matches the seeded folder.
    assert_eq!(roles::DRAFTS, "drafts");

    let draft_id = core
        .save_draft(draft_args(1, vec![token_for(&core, &secret).await]))
        .await
        .unwrap()
        .draft_id;

    let stored = stored_paths(&core, draft_id).await;
    assert_eq!(stored.len(), 1);
    let stored = stored[0].as_str();

    let staging_root = std::fs::canonicalize(paths.draft_attachments_dir()).unwrap();
    let stored_canon = std::fs::canonicalize(stored).unwrap();

    // The persisted path is the staged COPY, inside the app staging root...
    assert!(
        stored_canon.starts_with(&staging_root),
        "stored path {stored_canon:?} must live under staging root {staging_root:?}"
    );
    // ...never the original external path...
    assert_ne!(stored_canon, std::fs::canonicalize(&secret).unwrap());
    // ...and it holds the real bytes.
    assert_eq!(std::fs::read(&stored_canon).unwrap(), b"top secret bytes");
}

/// A renderer passing a raw source path - the exact pre-fix attack - is
/// refused and nothing is copied into staging.
#[tokio::test]
async fn save_draft_rejects_unapproved_external_path() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);

    // Stands in for ~/.ssh/id_rsa or the mail database itself.
    let secret = tmp.path().join("id_rsa");
    std::fs::write(&secret, b"PRIVATE KEY").unwrap();

    let core = Core::start(paths.clone()).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'me@example.com','imap','password','me','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts');",
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let err = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Staged {
                file_path: secret.to_string_lossy().into_owned(),
                filename: "id_rsa".into(),
            }],
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "expected ActionRejected, got {err:?}"
    );
    let root = paths.draft_attachments_dir();
    let copied: Vec<_> = std::fs::read_dir(&root)
        .map(|rd| rd.flatten().collect())
        .unwrap_or_default();
    assert!(copied.is_empty(), "staged copy made anyway: {copied:?}");
}

#[tokio::test]
async fn save_draft_neutralizes_traversal_filename_and_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);

    let src = tmp.path().join("payload.bin");
    std::fs::write(&src, b"xyz").unwrap();

    let core = Core::start(paths.clone()).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'me@example.com','imap','password','me','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts');",
            )?;
            Ok(())
        })
        .await
        .unwrap();

    // The staged name now comes from the real file's name - a renderer can
    // no longer supply a traversal name for staging at all.
    let draft_id = core
        .save_draft(draft_args(1, vec![token_for(&core, &src).await]))
        .await
        .unwrap()
        .draft_id;

    let staging_root = std::fs::canonicalize(paths.draft_attachments_dir()).unwrap();
    let staged = stored_paths(&core, draft_id).await[0].clone();
    let staged_canon = std::fs::canonicalize(&staged).unwrap();
    assert!(
        staged_canon.starts_with(&staging_root),
        "staged file escaped staging: {staged_canon:?}"
    );

    // Re-saving the draft, echoing back the already-staged path (as the reloaded
    // composer does), must keep it in place rather than fail or re-nest - and
    // an echoed display name cannot rename the persisted row.
    let result = core
        .save_draft(SaveDraftArgs {
            draft_id: Some(draft_id),
            ..draft_args(
                1,
                vec![DraftAttachmentIn::Staged {
                    file_path: staged.clone(),
                    filename: "../../../etc/evil".into(),
                }],
            )
        })
        .await
        .unwrap();
    assert_eq!(result.draft_id, draft_id);
    let restaged = std::fs::canonicalize(&stored_paths(&core, draft_id).await[0]).unwrap();
    assert_eq!(
        restaged, staged_canon,
        "already-staged path should be reused"
    );
    // And the traversal-ish echoed name was ignored: the row keeps the
    // filename stored when the file was first staged.
    match &result.attachments[0] {
        DraftAttachmentIn::Staged { filename, .. } => {
            assert_eq!(filename, "payload.bin");
        }
        other => panic!("expected a Staged attachment, got {other:?}"),
    }
}

/// Tokens are the only way a never-before-staged file reaches a draft, and a
/// token can stage exactly once.
#[tokio::test]
async fn save_draft_rejects_unknown_expired_and_consumed_tokens() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);

    let src = tmp.path().join("file.txt");
    std::fs::write(&src, b"data").unwrap();

    let core = Core::start(paths.clone()).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'me@example.com','imap','password','me','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts');",
            )?;
            Ok(())
        })
        .await
        .unwrap();

    // A token the registry never minted.
    let err = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Token {
                token: "not-a-real-token".into(),
            }],
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "unknown token: {err:?}"
    );

    // An already-expired token (minted past the 30-minute TTL via the test
    // hook in the registry).
    let old = std::time::Instant::now() - std::time::Duration::from_secs(31 * 60);
    let expired = core
        .attachment_approvals()
        .approve_at(vec![src.clone()], old, None)
        .unwrap();
    assert_eq!(expired.len(), 1);
    let err = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Token {
                token: expired[0].token.clone(),
            }],
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "expired token: {err:?}"
    );

    // A token consumed by one save cannot be replayed into another.
    let consumed = core.approve_attachment_sources(vec![src], None).unwrap();
    core.save_draft(draft_args(
        1,
        vec![DraftAttachmentIn::Token {
            token: consumed[0].token.clone(),
        }],
    ))
    .await
    .unwrap();
    let err = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Token {
                token: consumed[0].token.clone(),
            }],
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "replayed token: {err:?}"
    );
}

/// A staged path is bound to the draft that references it: another draft -
/// or a renderer that guessed the staging layout - cannot claim it.
#[tokio::test]
async fn save_draft_rejects_staged_path_of_other_draft() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;
    let a = tmp.path().join("a.txt");
    std::fs::write(&a, b"a").unwrap();

    let draft_a = core
        .save_draft(draft_args(1, vec![token_for(&core, &a).await]))
        .await
        .unwrap()
        .draft_id;
    let staged_a = stored_paths(&core, draft_a).await[0].clone();

    // Draft B tries to echo draft A's staged path.
    let err = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Staged {
                file_path: staged_a.clone(),
                filename: "a.txt".into(),
            }],
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "foreign staged path: {err:?}"
    );
    // A's staged copy and row are untouched.
    assert!(std::path::Path::new(&staged_a).exists());
    assert_eq!(stored_paths(&core, draft_a).await, vec![staged_a]);
}

/// A received attachment joins a forward by row id, resolved in Rust - the
/// webview never names a cache path.
#[tokio::test]
async fn forward_by_attachment_id_stages_cached_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let (paths, core) = setup_core(&tmp).await;

    // A downloaded attachment: an `attachments` row whose `file_path` cache
    // entry already exists on disk (see `get_attachment`).
    let cached = tmp.path().join("cached-report.pdf");
    std::fs::write(&cached, b"%PDF-forward-me").unwrap();
    core.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO messages
                   (id,account_id,thread_id,folder_id,uid,message_id,subject,date,
                    is_draft,is_outgoing,has_attachments,snippet,body_state)
                 VALUES (50,1,NULL,1,1,'<orig@x>','orig',1000,0,0,1,'s','cached')",
                [],
            )?;
            conn.execute(
                "INSERT INTO attachments (id,message_id,part_id,filename,mime_type,file_path)
                 VALUES (60,50,'2','report.pdf','application/pdf',?1)",
                [cached.to_string_lossy().into_owned()],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    // What `prepare_forward_attachment` does before save_draft: resolve the
    // row id to the cached bytes and mint a token for them.
    let prepared = core.prepare_forward_attachment(60, None).await.unwrap();
    assert_eq!(prepared.filename, "report.pdf");
    let draft_id = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Token {
                token: prepared.token,
            }],
        ))
        .await
        .unwrap()
        .draft_id;

    let staged = stored_paths(&core, draft_id).await;
    assert_eq!(staged.len(), 1);
    let staged = &staged[0];
    let staging_root = std::fs::canonicalize(paths.draft_attachments_dir()).unwrap();
    assert!(std::path::Path::new(staged).starts_with(&staging_root));
    assert_eq!(std::fs::read(staged).unwrap(), b"%PDF-forward-me");
    // The persisted display name comes from the attachment row.
    let name: String = core
        .db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT filename FROM draft_attachments WHERE draft_id = ?1",
                [draft_id],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(name, "report.pdf");
}

// -----------------------------------------------------------------------
// Lifecycle of the staged copies themselves (item 3): orphaned on re-save,
// deleted with the draft, swept at startup, never outside the staging root.
// -----------------------------------------------------------------------

async fn setup_core(tmp: &tempfile::TempDir) -> (comail_core::config::Paths, Core) {
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = comail_core::config::Paths::for_tests(&data_dir);
    let core = Core::start(paths.clone()).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'me@example.com','imap','password','me','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts'),(3,1,'Trash','trash');",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    (paths, core)
}

/// A same-draft staged echo - what `get_draft` hands the reopened composer
/// and what it must send back unchanged on re-save.
fn att(path: &str, name: &str) -> DraftAttachmentIn {
    DraftAttachmentIn::Staged {
        file_path: path.to_string(),
        filename: name.into(),
    }
}

#[tokio::test]
async fn resave_deletes_file_of_removed_attachment() {
    let tmp = tempfile::tempdir().unwrap();
    let (paths, core) = setup_core(&tmp).await;
    let a = tmp.path().join("a.txt");
    let b = tmp.path().join("b.txt");
    std::fs::write(&a, b"a").unwrap();
    std::fs::write(&b, b"b").unwrap();

    let draft_id = core
        .save_draft(draft_args(1, vec![token_for(&core, &a).await]))
        .await
        .unwrap()
        .draft_id;
    let staged_a = stored_paths(&core, draft_id).await[0].clone();
    assert!(std::path::Path::new(&staged_a).exists());

    // Re-save with a different attachment: a.txt's staged copy is orphaned.
    let draft_id = core
        .save_draft(SaveDraftArgs {
            draft_id: Some(draft_id),
            ..draft_args(1, vec![token_for(&core, &b).await])
        })
        .await
        .unwrap()
        .draft_id;
    assert!(
        !std::path::Path::new(&staged_a).exists(),
        "orphaned staged file left on disk"
    );
    assert!(
        !std::path::Path::new(&staged_a).parent().unwrap().exists(),
        "orphaned staging subdirectory left on disk"
    );
    let staged_b = stored_paths(&core, draft_id).await[0].clone();
    let root_canon = std::fs::canonicalize(paths.draft_attachments_dir()).unwrap();
    assert!(std::path::Path::new(&staged_b).starts_with(&root_canon));
    assert!(std::path::Path::new(&staged_b).exists());

    // Re-save keeping b.txt: its staged file survives.
    core.save_draft(SaveDraftArgs {
        draft_id: Some(draft_id),
        ..draft_args(1, vec![att(&staged_b, "b.txt")])
    })
    .await
    .unwrap();
    assert!(std::path::Path::new(&staged_b).exists());
}

#[tokio::test]
async fn delete_draft_removes_staged_files_local_and_remote() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;
    let src = tmp.path().join("f.txt");
    std::fs::write(&src, b"f").unwrap();

    // Local-only draft (uid NULL -> message row deleted).
    let local_id = core
        .save_draft(draft_args(1, vec![token_for(&core, &src).await]))
        .await
        .unwrap()
        .draft_id;
    let local_path = stored_paths(&core, local_id).await[0].clone();
    core.delete_draft(local_id).await.unwrap();
    assert!(!std::path::Path::new(&local_path).exists());
    assert!(!std::path::Path::new(&local_path).parent().unwrap().exists());

    // Remote draft (uid set -> message moved to Trash, row survives): the
    // staged copy must still go.
    let remote_id = core
        .save_draft(draft_args(1, vec![token_for(&core, &src).await]))
        .await
        .unwrap()
        .draft_id;
    let remote_path = stored_paths(&core, remote_id).await[0].clone();
    core.db
        .write(move |conn| {
            conn.execute("UPDATE messages SET uid = 7 WHERE id = ?1", [remote_id])?;
            Ok(())
        })
        .await
        .unwrap();
    core.delete_draft(remote_id).await.unwrap();
    assert!(
        !std::path::Path::new(&remote_path).exists(),
        "staged file survived remote-draft delete"
    );
    let rows: i64 = core
        .db
        .read(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM draft_attachments WHERE draft_id = ?1",
                [remote_id],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(rows, 0, "attachment rows kept on the trashed message");
}

#[tokio::test]
async fn delete_draft_never_removes_paths_outside_staging_root() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;
    let outside = tmp.path().join("important.txt");
    std::fs::write(&outside, b"do not delete").unwrap();

    let draft_id = core
        .save_draft(draft_args(1, vec![]))
        .await
        .unwrap()
        .draft_id;
    let outside_str = outside.to_string_lossy().into_owned();
    core.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO draft_attachments (draft_id,file_path,filename,mime_type)
                 VALUES (?1,?2,'important.txt','text/plain')",
                rusqlite::params![draft_id, outside_str],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    core.delete_draft(draft_id).await.unwrap();
    assert!(
        outside.exists(),
        "a DB path outside the staging root was deleted"
    );
}

#[tokio::test]
async fn startup_sweep_removes_unreferenced_dirs_but_not_recent_or_referenced() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;
    let src = tmp.path().join("s.txt");
    std::fs::write(&src, b"s").unwrap();
    let root =
        comail_core::config::Paths::for_tests(&tmp.path().join("data")).draft_attachments_dir();

    let draft_id = core
        .save_draft(draft_args(1, vec![token_for(&core, &src).await]))
        .await
        .unwrap()
        .draft_id;
    let staged = stored_paths(&core, draft_id).await[0].clone();

    // A "recent" unreferenced dir (as an in-flight save would leave) is
    // protected by the one-hour grace window.
    let recent = root.join("recent_orphan");
    std::fs::create_dir_all(&recent).unwrap();
    std::fs::write(recent.join("x.bin"), b"x").unwrap();
    let n = comail_core::sweep_draft_attachment_staging(
        &core.db,
        &root,
        std::time::Duration::from_secs(3600),
    )
    .await
    .unwrap();
    assert_eq!(n, 0);
    assert!(recent.exists());

    // With no grace window the unreferenced dir goes; the draft's own staged
    // dir (still referenced by its row) stays, and the root survives.
    let n = comail_core::sweep_draft_attachment_staging(&core.db, &root, std::time::Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(n, 1);
    assert!(!recent.exists());
    assert!(std::path::Path::new(&staged).exists());
    assert!(root.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn staged_symlink_pointing_outside_is_never_followed_for_deletion() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;
    let outside = tmp.path().join("outside-secret.txt");
    std::fs::write(&outside, b"keep me").unwrap();

    // A crafted row: the stored path sits inside the staging root but is a
    // symlink resolving outside it. Deleting "the file at the row's path"
    // must not follow the link.
    let draft_id = core
        .save_draft(draft_args(1, vec![]))
        .await
        .unwrap()
        .draft_id;
    let staging_root =
        comail_core::config::Paths::for_tests(&tmp.path().join("data")).draft_attachments_dir();
    let link_dir = staging_root.join("crafted");
    std::fs::create_dir_all(&link_dir).unwrap();
    let link = link_dir.join("evil.txt");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let link_str = link.to_string_lossy().into_owned();
    core.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO draft_attachments (draft_id,file_path,filename,mime_type)
                 VALUES (?1,?2,'evil.txt','text/plain')",
                rusqlite::params![draft_id, link_str],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    core.delete_draft(draft_id).await.unwrap();
    assert!(
        outside.exists(),
        "deletion followed a staged symlink outside the root"
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"keep me");
}

#[tokio::test]
async fn sweep_aborts_without_deleting_when_the_reference_query_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;
    let root =
        comail_core::config::Paths::for_tests(&tmp.path().join("data")).draft_attachments_dir();
    let orphan = root.join("old_orphan");
    std::fs::create_dir_all(&orphan).unwrap();
    std::fs::write(orphan.join("x.bin"), b"x").unwrap();

    // Break the referenced-paths query: the sweep must surface the error and
    // delete nothing rather than GC against a guessed-empty reference set.
    core.db
        .write(|conn| {
            conn.execute_batch("DROP TABLE draft_attachments")?;
            Ok(())
        })
        .await
        .unwrap();
    let result =
        comail_core::sweep_draft_attachment_staging(&core.db, &root, std::time::Duration::ZERO)
            .await;
    assert!(result.is_err(), "sweep must fail when the query fails");
    assert!(orphan.exists(), "sweep deleted despite the query error");
}

#[cfg(unix)]
#[tokio::test]
async fn sweep_keeps_entries_with_future_or_unreadable_mtime() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;
    let root =
        comail_core::config::Paths::for_tests(&tmp.path().join("data")).draft_attachments_dir();
    std::fs::create_dir_all(&root).unwrap();
    let future = root.join("future_orphan");
    std::fs::create_dir_all(&future).unwrap();
    std::fs::write(future.join("x.bin"), b"x").unwrap();

    // mtime in the future: elapsed() fails, so the entry must be treated as
    // fresh (a racing save's staging), not GC'd.
    let f = std::fs::File::open(&future).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(7200))
        .unwrap();
    let n = comail_core::sweep_draft_attachment_staging(
        &core.db,
        &root,
        std::time::Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(n, 0);
    assert!(future.exists(), "future-mtime entry was swept");
}

#[tokio::test]
async fn remove_account_removes_its_staged_draft_attachments() {
    // remove_account purges credentials, which otherwise hits the OS keyring
    // and blocks on headless test machines; the insecure file backend is
    // what the send e2e uses for the same reason.
    let creds =
        std::env::temp_dir().join(format!("comail-staging-creds-{}.json", std::process::id()));
    // SAFETY: set before Core::start, matching the established test idiom.
    unsafe { std::env::set_var("COMAIL_CREDENTIALS_INSECURE_FILE", &creds) };
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);
    let core = Core::start(paths.clone()).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'a@example.com','imap','password','a','h',993,'h',465,0),
                          (2,'b@example.com','imap','password','b','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts'), (2,2,'Drafts','drafts');",
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let src = tmp.path().join("keep.bin");
    std::fs::write(&src, b"payload").unwrap();
    let draft_id = core
        .save_draft(draft_args(2, vec![token_for(&core, &src).await]))
        .await
        .unwrap()
        .draft_id;
    let stored = stored_paths(&core, draft_id).await;
    assert_eq!(stored.len(), 1);
    let staged = std::path::PathBuf::from(&stored[0]);
    assert!(staged.exists());

    core.remove_account(2).await.unwrap();

    // The account cascade dropped the row AND the staged file went with it;
    // the per-file subdirectory is pruned too.
    assert!(!staged.exists(), "staged file left: {staged:?}");
    assert!(!staged.parent().unwrap().exists());
}

// -----------------------------------------------------------------------
// The approval boundary itself: what may be minted, and use-time checks.
// -----------------------------------------------------------------------

#[tokio::test]
async fn approvals_skip_directories_and_missing_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;

    let dir = tmp.path().join("a-directory");
    std::fs::create_dir_all(&dir).unwrap();
    let missing = tmp.path().join("never-existed.bin");
    // A symlink to a directory is not a regular file either.
    #[cfg(unix)]
    let dir_link = tmp.path().join("dir-link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&dir, &dir_link).unwrap();

    let approved = core
        .approve_attachment_sources(
            {
                #[cfg(unix)]
                {
                    vec![dir.clone(), dir_link.clone(), missing.clone()]
                }
                #[cfg(not(unix))]
                {
                    vec![dir.clone(), missing.clone()]
                }
            },
            None,
        )
        .unwrap();
    assert!(approved.is_empty(), "approved: {approved:?}");
}

/// Replacing the approved file with a symlink (or a directory) at the same
/// path must fail use-time validation instead of copying the new target.
#[cfg(unix)]
#[tokio::test]
async fn save_draft_refuses_token_after_symlink_swap() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;

    let picked = tmp.path().join("picked.txt");
    std::fs::write(&picked, b"user picked this").unwrap();
    let victim = tmp.path().join("victim.txt");
    std::fs::write(&victim, b"never approved").unwrap();
    let att = token_for(&core, &picked).await;

    // Swap the approved path for a symlink to a different file: the
    // canonical path at use no longer equals the approved canonical path.
    std::fs::remove_file(&picked).unwrap();
    std::os::unix::fs::symlink(&victim, &picked).unwrap();

    let err = core.save_draft(draft_args(1, vec![att])).await.unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "symlink swap: {err:?}"
    );

    // Same for a directory swapped in under the approved name.
    let picked2 = tmp.path().join("picked2.txt");
    std::fs::write(&picked2, b"also picked").unwrap();
    let att2 = token_for(&core, &picked2).await;
    std::fs::remove_file(&picked2).unwrap();
    std::fs::create_dir_all(&picked2).unwrap();

    let err = core
        .save_draft(draft_args(1, vec![att2]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "dir swap: {err:?}"
    );
}

/// The drop exchange: paths Rust observed falling on the window mint tokens;
/// anything the webview merely asserts was dropped is refused. This is the
/// trust boundary - `record_os_drop` is called only by the Rust webview-event
/// handler, which tests stand in for.
#[tokio::test]
async fn claim_dropped_attachments_accepts_only_rust_observed_drops() {
    let tmp = tempfile::tempdir().unwrap();
    let (paths, core) = setup_core(&tmp).await;

    let dropped = tmp.path().join("dropped.png");
    std::fs::write(&dropped, b"png").unwrap();
    let not_dropped = tmp.path().join("not-dropped.txt");
    std::fs::write(&not_dropped, b"nope").unwrap();

    // Rust observed this drop on the window.
    core.record_os_drop(std::slice::from_ref(&dropped));

    // Exchanging the observed path works...
    let claimed = core
        .claim_dropped_attachments(&[dropped.to_string_lossy().into_owned()], None)
        .unwrap()
        .approved;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].filename, "dropped.png");

    // ...once: the drop record is consumed by the exchange, and a duplicate
    // claim for it (e.g. a double-registered listener) is a silent no-op.
    let dup = core
        .claim_dropped_attachments(&[dropped.to_string_lossy().into_owned()], None)
        .unwrap();
    assert!(dup.approved.is_empty());

    // A path the OS never dropped - even though it exists and is a regular
    // file - cannot be claimed.
    core.record_os_drop(std::slice::from_ref(&dropped));
    let err = core
        .claim_dropped_attachments(&[not_dropped.to_string_lossy().into_owned()], None)
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "un-observed path: {err:?}"
    );
    // And a mixed claim fails whole-call, leaving the real drop claimable.
    let err = core
        .claim_dropped_attachments(
            &[
                dropped.to_string_lossy().into_owned(),
                not_dropped.to_string_lossy().into_owned(),
            ],
            None,
        )
        .unwrap_err();
    assert!(matches!(
        err,
        comail_core::error::CoreError::ActionRejected(_)
    ));
    assert!(
        core.claim_dropped_attachments(&[dropped.to_string_lossy().into_owned()], None)
            .is_ok(),
        "the genuine drop should survive a failed mixed claim"
    );

    // The claimed token stages like a picked file.
    core.record_os_drop(std::slice::from_ref(&dropped));
    let claimed = core
        .claim_dropped_attachments(&[dropped.to_string_lossy().into_owned()], None)
        .unwrap()
        .approved;
    let draft_id = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Token {
                token: claimed[0].token.clone(),
            }],
        ))
        .await
        .unwrap()
        .draft_id;
    let staged = stored_paths(&core, draft_id).await;
    assert_eq!(staged.len(), 1);
    let staging_root = std::fs::canonicalize(paths.draft_attachments_dir()).unwrap();
    assert!(std::path::Path::new(&staged[0]).starts_with(&staging_root));
    assert_eq!(std::fs::read(&staged[0]).unwrap(), b"png");
}

// -----------------------------------------------------------------------
// Review round 1: token lifecycle (commit-only consumption, nonce binding)
// and same-session adoption for a recreated draft.
// -----------------------------------------------------------------------

/// A token is consumed only when the save commits: when ANY attachment in
/// the same request fails, every token in the request stays usable and no
/// staged copy survives. The retry then stages normally.
#[tokio::test]
async fn failed_save_rolls_back_tokens_and_cleans_staged_files() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);

    let ok = tmp.path().join("ok.txt");
    let also_ok = tmp.path().join("also-ok.txt");
    std::fs::write(&ok, b"ok").unwrap();
    std::fs::write(&also_ok, b"also").unwrap();

    let core = Core::start(paths.clone()).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'me@example.com','imap','password','me','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts');",
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let tokens = core
        .approve_attachment_sources(vec![ok.clone(), also_ok.clone()], None)
        .unwrap();
    let stage_root = paths.draft_attachments_dir();
    std::fs::create_dir_all(&stage_root).unwrap();
    let stage_root = std::fs::canonicalize(&stage_root).unwrap();
    let before: Vec<_> = std::fs::read_dir(&stage_root).unwrap().collect();

    // One bad entry anywhere in the request fails the whole save.
    let err = core
        .save_draft(draft_args(
            1,
            vec![
                DraftAttachmentIn::Token {
                    token: tokens[0].token.clone(),
                },
                DraftAttachmentIn::Token {
                    token: "bogus".into(),
                },
                DraftAttachmentIn::Token {
                    token: tokens[1].token.clone(),
                },
            ],
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        comail_core::error::CoreError::ActionRejected(_)
    ));

    // Nothing staged survives from the failed attempt.
    let after: Vec<_> = std::fs::read_dir(&stage_root).unwrap().collect();
    assert_eq!(before.len(), after.len());

    // Both tokens are still valid - the very next save stages them.
    let draft_id = core
        .save_draft(draft_args(
            1,
            tokens
                .into_iter()
                .map(|t| DraftAttachmentIn::Token { token: t.token })
                .collect(),
        ))
        .await
        .unwrap()
        .draft_id;
    assert_eq!(stored_paths(&core, draft_id).await.len(), 2);
}

/// A draft deleted mid-session and recreated under the same composer nonce
/// adopts the staged files the vanished draft produced; a different nonce
/// cannot adopt them.
#[tokio::test]
async fn recreated_draft_adopts_own_sessions_staged_files() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);

    let src = tmp.path().join("keep.pdf");
    std::fs::write(&src, b"keep").unwrap();

    let core = Core::start(paths).await.unwrap();
    core.db
        .write(|conn| {
            conn.execute_batch(
                "INSERT INTO accounts
                   (id,email,provider,auth_kind,username,imap_host,imap_port,smtp_host,smtp_port,created_at)
                   VALUES (1,'me@example.com','imap','password','me','h',993,'h',465,0);
                 INSERT INTO folders (id,account_id,imap_name,role)
                   VALUES (1,1,'Drafts','drafts');",
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let nonce = Some("session-1".to_string());
    let minted = core
        .approve_attachment_sources(vec![src], nonce.clone())
        .unwrap();
    let args = SaveDraftArgs {
        attachments: vec![DraftAttachmentIn::Token {
            token: minted[0].token.clone(),
        }],
        composer_nonce: nonce.clone(),
        ..draft_args(1, Vec::new())
    };
    let draft_id = core.save_draft(args).await.unwrap().draft_id;
    let staged = stored_paths(&core, draft_id).await[0].clone();

    // The draft vanishes (server-side delete the local client didn't know).
    core.db
        .write(move |conn| {
            conn.execute("DELETE FROM messages WHERE id = ?1", [draft_id])?;
            conn.execute(
                "DELETE FROM draft_attachments WHERE draft_id = ?1",
                [draft_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    // Same session, draftless re-save (draft id dropped by the saver):
    // the staged file is adopted instead of rejected.
    let adopted = core
        .save_draft(SaveDraftArgs {
            attachments: vec![DraftAttachmentIn::Staged {
                file_path: staged.clone(),
                filename: "keep.pdf".into(),
            }],
            composer_nonce: nonce.clone(),
            ..draft_args(1, Vec::new())
        })
        .await
        .unwrap()
        .draft_id;
    assert_eq!(stored_paths(&core, adopted).await, vec![staged.clone()]);

    // A second vanished draft + a DIFFERENT session nonce: no adoption.
    core.db
        .write(move |conn| {
            conn.execute("DELETE FROM messages WHERE id = ?1", [adopted])?;
            conn.execute(
                "DELETE FROM draft_attachments WHERE draft_id = ?1",
                [adopted],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let err = core
        .save_draft(SaveDraftArgs {
            attachments: vec![DraftAttachmentIn::Staged {
                file_path: staged.clone(),
                filename: "keep.pdf".into(),
            }],
            composer_nonce: Some("other-session".into()),
            ..draft_args(1, Vec::new())
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "foreign nonce: {err:?}"
    );
    // The file was not touched either way.
    assert!(std::path::Path::new(&staged).exists());
}

// -----------------------------------------------------------------------
// Review round 2: staged-path single-owner invariant + per-draft limits.
// -----------------------------------------------------------------------

/// The attack an over-broad produced map made possible: get_draft(D1) hands
/// out D1's staged path; echoing it on a save of D1 must NOT let a later
/// draftless save adopt it while D1 still references the file. The DB-level
/// invariant rejects step 3 even though the session produced the file.
#[tokio::test]
async fn staged_echo_of_live_draft_cannot_be_adopted() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;

    let src = tmp.path().join("doc.pdf");
    std::fs::write(&src, b"doc").unwrap();
    let nonce = Some("session-9".to_string());
    let minted = core
        .approve_attachment_sources(vec![src], nonce.clone())
        .unwrap();

    // 1. D1 saves with the token: X is fresh-staged and produced under M.
    let draft_id = core
        .save_draft(SaveDraftArgs {
            attachments: vec![DraftAttachmentIn::Token {
                token: minted[0].token.clone(),
            }],
            composer_nonce: nonce.clone(),
            ..draft_args(1, Vec::new())
        })
        .await
        .unwrap()
        .draft_id;
    let staged = stored_paths(&core, draft_id).await[0].clone();

    // 2. D1 re-saves echoing its staged path under the same nonce (what
    //    get_draft + save looks like). Must not re-record it as produced.
    core.save_draft(SaveDraftArgs {
        draft_id: Some(draft_id),
        attachments: vec![DraftAttachmentIn::Staged {
            file_path: staged.clone(),
            filename: "doc.pdf".into(),
        }],
        composer_nonce: nonce.clone(),
        ..draft_args(1, Vec::new())
    })
    .await
    .unwrap();

    // 3. A draftless save (a "new draft") under nonce M tries to adopt X.
    //    produced_by says yes; the single-owner invariant says no - D1
    //    still references the file.
    let err = core
        .save_draft(SaveDraftArgs {
            attachments: vec![DraftAttachmentIn::Staged {
                file_path: staged.clone(),
                filename: "doc.pdf".into(),
            }],
            composer_nonce: nonce,
            ..draft_args(1, Vec::new())
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "live-owner adoption must be rejected: {err:?}"
    );
    // D1 is intact: its row and its file are untouched.
    assert_eq!(stored_paths(&core, draft_id).await, vec![staged.clone()]);
    assert!(std::path::Path::new(&staged).exists());
}

/// The DB-level invariant itself: a save must refuse to give draft B a row
/// for a staged file draft A already references - even if B's rows were
/// corrupted into "owning" the echo.
#[tokio::test]
async fn two_drafts_cannot_share_a_staged_path() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;

    let src = tmp.path().join("shared.pdf");
    std::fs::write(&src, b"shared").unwrap();
    let draft_a = core
        .save_draft(draft_args(1, vec![token_for(&core, &src).await]))
        .await
        .unwrap()
        .draft_id;
    let draft_b = core
        .save_draft(draft_args(1, vec![]))
        .await
        .unwrap()
        .draft_id;
    let staged = stored_paths(&core, draft_a).await[0].clone();

    // Corrupt B's rows to point at A's file (simulates any path by which B
    // "learns" A's staged path - the invariant must hold regardless).
    let row_path = staged.clone();
    core.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO draft_attachments (draft_id,file_path,filename,mime_type)
                 VALUES (?1,?2,'shared.pdf','application/pdf')",
                rusqlite::params![draft_b, row_path],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let err = core
        .save_draft(SaveDraftArgs {
            draft_id: Some(draft_b),
            attachments: vec![DraftAttachmentIn::Staged {
                file_path: staged.clone(),
                filename: "shared.pdf".into(),
            }],
            ..draft_args(1, Vec::new())
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "cross-draft share must be rejected: {err:?}"
    );
    // The transaction rolled back: B's rows were not deleted/reinserted,
    // and A's row + file are untouched.
    assert_eq!(stored_paths(&core, draft_a).await, vec![staged.clone()]);
    assert!(std::path::Path::new(&staged).exists());
}

/// Per-draft bounds: over 100 attachments or over 150 MB total fails the
/// save outright (and the staged copies it made are removed).
#[tokio::test]
async fn per_draft_attachment_limits_are_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let (paths, core) = setup_core(&tmp).await;
    std::fs::create_dir_all(paths.draft_attachments_dir()).unwrap();
    let staging_root = std::fs::canonicalize(paths.draft_attachments_dir()).unwrap();

    // Too many: 101 one-byte files.
    let mut atts = Vec::new();
    for i in 0..101usize {
        let f = tmp.path().join(format!("f{i}.txt"));
        std::fs::write(&f, b"x").unwrap();
        let approved = core.approve_attachment_sources(vec![f], None).unwrap();
        atts.push(DraftAttachmentIn::Token {
            token: approved[0].token.clone(),
        });
    }
    let err = core.save_draft(draft_args(1, atts)).await.unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "count limit: {err:?}"
    );
    // The staged copies of a rejected save were cleaned up.
    let leftovers = std::fs::read_dir(&staging_root).unwrap().count();
    assert_eq!(leftovers, 0, "staged copies of a rejected save leaked");

    // Too big: one sparse 160 MB file (sparse: no real disk cost).
    let big = tmp.path().join("big.bin");
    let file = std::fs::File::create(&big).unwrap();
    file.set_len(160 * 1024 * 1024).unwrap();
    drop(file);
    let approved = core.approve_attachment_sources(vec![big], None).unwrap();
    let err = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn::Token {
                token: approved[0].token.clone(),
            }],
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "byte limit: {err:?}"
    );
    let leftovers = std::fs::read_dir(&staging_root).unwrap().count();
    assert_eq!(leftovers, 0);
}

/// A prepared forward whose cached file would push the session's
/// not-yet-consumed prepared bytes over the cap is refused - a prepare/save
/// loop cannot queue unbounded bytes. Sparse files keep this cheap.
#[tokio::test]
async fn prepared_forward_bytes_are_capped_per_session() {
    let tmp = tempfile::tempdir().unwrap();
    let (_paths, core) = setup_core(&tmp).await;

    let cached = tmp.path().join("huge.bin");
    let file = std::fs::File::create(&cached).unwrap();
    file.set_len(600 * 1024 * 1024).unwrap();
    drop(file);
    let cache_path = cached.to_string_lossy().into_owned();
    core.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO messages
                   (id,account_id,thread_id,folder_id,uid,message_id,subject,date,
                    is_draft,is_outgoing,has_attachments,snippet,body_state)
                 VALUES (70,1,NULL,1,1,'<big@x>','big',1000,0,0,1,'s','cached')",
                [],
            )?;
            conn.execute(
                "INSERT INTO attachments (id,message_id,part_id,filename,mime_type,file_path)
                 VALUES (71,70,'2','huge.bin','application/octet-stream',?1)",
                [cache_path],
            )?;
            Ok(())
        })
        .await
        .unwrap();

    let err = core
        .prepare_forward_attachment(71, Some("session-big".into()))
        .await
        .unwrap_err();
    assert!(
        matches!(err, comail_core::error::CoreError::ActionRejected(_)),
        "prepared bytes cap: {err:?}"
    );
}
