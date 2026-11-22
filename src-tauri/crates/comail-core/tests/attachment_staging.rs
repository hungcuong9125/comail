//! Security regression test for the draft-attachment staging fix.
//!
//! `save_draft` accepts an attachment `file_path` straight from the frontend
//! IPC. Historically that exact path was read off disk at dispatch and mailed,
//! so a malicious/compromised renderer could attach `~/.ssh/id_rsa` or
//! `/etc/passwd` and exfiltrate it. The fix copies every picked file into an
//! app-managed staging dir at save time and persists only the staged path;
//! dispatch additionally refuses to read anything outside that dir. This test
//! locks in the save-time control (the primary boundary) end-to-end.

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
    }
}

#[tokio::test]
async fn save_draft_stages_external_file_into_app_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let paths = Paths::for_tests(&data_dir);

    // A "secret" file living OUTSIDE the app data dir - stands in for the
    // arbitrary local file a malicious frontend might try to attach & send.
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
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn {
                file_path: secret.to_string_lossy().into_owned(),
                filename: "secret.txt".into(),
            }],
        ))
        .await
        .unwrap();

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

    // A path-traversal filename must not escape the staging subdir.
    let draft_id = core
        .save_draft(draft_args(
            1,
            vec![DraftAttachmentIn {
                file_path: src.to_string_lossy().into_owned(),
                filename: "../../../../etc/evil".into(),
            }],
        ))
        .await
        .unwrap();

    let staging_root = std::fs::canonicalize(paths.draft_attachments_dir()).unwrap();
    let staged = stored_paths(&core, draft_id).await[0].clone();
    let staged_canon = std::fs::canonicalize(&staged).unwrap();
    assert!(
        staged_canon.starts_with(&staging_root),
        "traversal filename escaped staging: {staged_canon:?}"
    );

    // Re-saving the draft, echoing back the already-staged path (as the reloaded
    // composer does), must keep it in place rather than fail or re-nest.
    let draft_id2 = core
        .save_draft(SaveDraftArgs {
            draft_id: Some(draft_id),
            ..draft_args(
                1,
                vec![DraftAttachmentIn {
                    file_path: staged.clone(),
                    filename: "evil".into(),
                }],
            )
        })
        .await
        .unwrap();
    assert_eq!(draft_id2, draft_id);
    let restaged = std::fs::canonicalize(&stored_paths(&core, draft_id).await[0]).unwrap();
    assert_eq!(
        restaged, staged_canon,
        "already-staged path should be reused"
    );
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

fn att(path: &std::path::Path, name: &str) -> DraftAttachmentIn {
    DraftAttachmentIn {
        file_path: path.to_string_lossy().into_owned(),
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
        .save_draft(draft_args(1, vec![att(&a, "a.txt")]))
        .await
        .unwrap();
    let staged_a = stored_paths(&core, draft_id).await[0].clone();
    assert!(std::path::Path::new(&staged_a).exists());

    // Re-save with a different attachment: a.txt's staged copy is orphaned.
    let draft_id = core
        .save_draft(SaveDraftArgs {
            draft_id: Some(draft_id),
            ..draft_args(1, vec![att(&b, "b.txt")])
        })
        .await
        .unwrap();
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
        ..draft_args(
            1,
            vec![DraftAttachmentIn {
                file_path: staged_b.clone(),
                filename: "b.txt".into(),
            }],
        )
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
        .save_draft(draft_args(1, vec![att(&src, "f.txt")]))
        .await
        .unwrap();
    let local_path = stored_paths(&core, local_id).await[0].clone();
    core.delete_draft(local_id).await.unwrap();
    assert!(!std::path::Path::new(&local_path).exists());
    assert!(!std::path::Path::new(&local_path).parent().unwrap().exists());

    // Remote draft (uid set -> message moved to Trash, row survives): the
    // staged copy must still go.
    let remote_id = core
        .save_draft(draft_args(1, vec![att(&src, "f.txt")]))
        .await
        .unwrap();
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

    let draft_id = core.save_draft(draft_args(1, vec![])).await.unwrap();
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
        .save_draft(draft_args(1, vec![att(&src, "s.txt")]))
        .await
        .unwrap();
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
    let draft_id = core.save_draft(draft_args(1, vec![])).await.unwrap();
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
