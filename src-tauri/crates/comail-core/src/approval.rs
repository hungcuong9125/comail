//! Session registry of local files the user approved for draft attachments.
//!
//! The webview is never the authority on which local files may leave the
//! machine inside an email: a renderer that could pass any path to
//! `save_draft` (an XSS, a compromised dependency) would turn the app into an
//! arbitrary-file exfiltration channel. Approvals are therefore minted only
//! by trusted Rust paths - the native file dialog, an OS drop observed on the
//! window, or internal callers (a generated calendar invite, a forwarded
//! attachment resolved by row id) - and `save_draft` accepts only the opaque
//! tokens this registry hands out.
//!
//! Hardening:
//! - tokens are unguessable random strings, valid for [`APPROVAL_TTL`] and
//!   single-use: `save_draft` checks one out while its save is in flight and
//!   consumes it only when the draft transaction commits, so a failed save
//!   can simply be retried;
//! - tokens are bound to the composer nonce that minted them (`pick` and
//!   `claim` take the nonce the composer generated for itself). What this
//!   does: a token minted for one composer session cannot be spent by a
//!   save naming another session's nonce, so tokens and produced-staged
//!   files cannot leak across composer sessions. What it does NOT do: a
//!   script that can call these commands at all can still attach every
//!   file the user explicitly chose (it can mint its own nonce and use it
//!   end to end) - the nonce is a session boundary, not a secret;
//! - webview-facing nonces are namespaced (`js:` prefix applied in the
//!   command layer), so the nonce-less scope internal approvals use can
//!   never be produced by IPC - internal tokens are unreachable from JS;
//! - the registry is capped so a misbehaving renderer cannot grow it;
//! - OS drops are registered here by Rust itself (the webview event handler
//!   observes the real drop) and expire quickly - the webview can only
//!   exchange paths Rust already saw fall on the window. A consumed drop is
//!   remembered briefly so a duplicate claim (a double-registered JS
//!   listener) is a silent no-op, not an error toast;
//! - staged files a save produced are remembered per composer nonce, so a
//!   draft deleted and recreated inside one session can adopt its own staged
//!   files - and only that session's files;
//! - the canonical path recorded at approval time is re-checked when the
//!   token is used, so a symlink swap between pick and save cannot redirect
//!   the copy.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::Result;
use crate::error::CoreError;
use crate::models::{ApprovedAttachment, DropClaim, SkippedDrop};

/// How long an approval token stays usable after the user gesture that
/// created it. Covers a long compose session without making yesterday's
/// picks attachable.
const APPROVAL_TTL: Duration = Duration::from_secs(30 * 60);

/// How long an OS drop the webview has not yet exchanged stays claimable.
/// The frontend exchanges paths the moment the drop event arrives, so this
/// only needs to outlive event delivery - not a user pause.
const DROP_TTL: Duration = Duration::from_secs(2 * 60);

/// Live approval cap; a new approval past this evicts the oldest.
const MAX_APPROVALS: usize = 256;

/// Unclaimed-drop cap, same rationale as [`MAX_APPROVALS`]. The consumed-drop
/// memory shares the cap: both only ever hold recent OS events.
const MAX_PENDING_DROPS: usize = 512;

/// Cap on the per-nonce produced-paths memory (session-scale, not global).
const MAX_PRODUCED: usize = 1024;

/// A file the user approved for attaching, keyed by its opaque token.
#[derive(Clone)]
pub(crate) struct Approval {
    /// Canonical path recorded at approval time. Re-canonicalised at use and
    /// required to match, so a symlink swapped in after the pick cannot
    /// redirect the staged copy at another file.
    pub canonical_path: PathBuf,
    /// Display filename (bidi-stripped) recorded from the approved path.
    pub filename: String,
    /// Source size recorded at approval time (feeds the per-session
    /// pending-bytes cap on prepared forwards).
    pub size: u64,
    /// The composer nonce this approval is bound to, if any. `None` is the
    /// internal scope (calendar invites): the command layer namespaces every
    /// webview-supplied nonce, so no IPC value can ever equal it.
    nonce: Option<String>,
    pub at: Instant,
    /// Insertion order - deterministic eviction when entries share `at`.
    seq: u64,
}

/// Session registry of approved attachment sources. In-memory only: every
/// token dies with the process.
#[derive(Default)]
pub struct AttachmentApprovals {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// token -> approval
    approvals: HashMap<String, Approval>,
    /// Tokens checked out by an in-flight `save_draft`: a second save may not
    /// stage the same token concurrently. Removed by `commit` (token spent)
    /// or `rollback` (token usable again).
    in_flight: HashSet<String>,
    /// canonical path -> when the OS drop was observed. Paths land here only
    /// from the Rust-side webview drop handler; the webview exchanges them
    /// for tokens via `claim_drops` and may not register anything itself.
    pending_drops: HashMap<PathBuf, Instant>,
    /// canonical path -> when a drop was successfully claimed. Lets a
    /// duplicate claim (double-registered webview listener) no-op instead of
    /// looking like a path the OS never dropped.
    consumed_drops: HashMap<PathBuf, Instant>,
    /// canonical path -> an opaque, session-scoped alias the webview uses to
    /// dedupe picks/drops of the same file without ever learning its path.
    source_keys: HashMap<PathBuf, String>,
    /// canonical staged path -> (composer nonce, seq) of the save that
    /// produced it. Drives the draft-recreated adoption rule: a `Staged`
    /// entry is claimable for a draftless save only when the same session
    /// produced that staged file earlier.
    produced: HashMap<PathBuf, (String, u64)>,
    /// Monotonic insertion counter for approval/produced entries.
    next_seq: u64,
}

impl Inner {
    fn evict_expired(&mut self, now: Instant) {
        self.approvals
            .retain(|_, a| now.duration_since(a.at) < APPROVAL_TTL);
        self.pending_drops
            .retain(|_, t| now.duration_since(*t) < DROP_TTL);
        self.consumed_drops
            .retain(|_, t| now.duration_since(*t) < DROP_TTL);
    }

    /// Evict the oldest approval not checked out by an in-flight save:
    /// removing one would strand its token in `in_flight` forever.
    fn evict_oldest_approval(&mut self) {
        while self.approvals.len() >= MAX_APPROVALS {
            let Some(oldest) = self
                .approvals
                .iter()
                .filter(|(t, _)| !self.in_flight.contains(*t))
                .min_by_key(|(_, a)| a.seq)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.approvals.remove(&oldest);
        }
    }

    /// Drop `key` entries (oldest seq) until `map` is under `cap`.
    fn trim_produced(&mut self) {
        while self.produced.len() >= MAX_PRODUCED {
            let Some(oldest) = self
                .produced
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.produced.remove(&oldest);
        }
    }

    /// The webview-facing dedupe key for a canonical path: an opaque session
    /// alias, stable per path so re-picking/re-dropping the same file reads
    /// as the same source without handing the real path to JS.
    fn source_key(&mut self, canonical: &std::path::Path) -> String {
        self.source_keys
            .entry(canonical.to_path_buf())
            .or_insert_with(mint_token)
            .clone()
    }
}

/// Opaque approval token: two `rand_token()`s (~103 bits) so it is
/// unguessable even for a renderer that can call `save_draft` in a loop.
fn mint_token() -> String {
    format!("{}{}", crate::mime::rand_token(), crate::mime::rand_token())
}

/// `path` must exist and be a regular file (directories, devices, FIFOs,
/// missing paths fail).
fn regular_file(path: &PathBuf) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.file_type().is_file())
}

impl AttachmentApprovals {
    /// Mint approval tokens for user-picked local files. Callers must be
    /// trusted Rust code: the native file dialog handler, or internal code
    /// that generated/resolved the file itself (a calendar invite, a
    /// forwarded attachment's cache entry). `nonce` binds the tokens to the
    /// composer session asking for them; internal callers pass `None`.
    /// Non-regular files (directories, devices, FIFOs, missing paths) are
    /// skipped.
    pub fn approve(
        &self,
        paths: Vec<PathBuf>,
        nonce: Option<String>,
    ) -> Result<Vec<ApprovedAttachment>> {
        self.approve_at(paths, Instant::now(), nonce)
    }

    /// [`approve`] for a single internal source whose display name is not
    /// its path basename - a forward's cached bytes carry the original
    /// attachment's filename, not the cache file's name.
    pub(crate) fn approve_named(
        &self,
        path: PathBuf,
        filename: &str,
        nonce: Option<String>,
    ) -> Result<ApprovedAttachment> {
        let mut inner = self.inner.lock().unwrap();
        inner.evict_expired(Instant::now());
        let canonical = std::fs::canonicalize(&path)
            .map_err(|e| CoreError::Other(format!("attachment {filename}: {e}")))?;
        if !regular_file(&canonical) {
            return Err(CoreError::ActionRejected(format!(
                "attachment {filename}: not a regular file"
            )));
        }
        if inner.approvals.len() >= MAX_APPROVALS {
            inner.evict_oldest_approval();
        }
        let filename = crate::display_filename(filename);
        let mime_type = Some(crate::queue::mime_guess_from_name(&filename));
        let source = inner.source_key(&canonical);
        let token = mint_token();
        let seq = inner.next_seq;
        inner.next_seq += 1;
        let at = Instant::now();
        let size = std::fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
        inner.approvals.insert(
            token.clone(),
            Approval {
                canonical_path: canonical.clone(),
                filename: filename.clone(),
                size,
                nonce,
                at,
                seq,
            },
        );
        Ok(ApprovedAttachment {
            token,
            filename,
            source,
            size,
            mime_type,
        })
    }

    /// [`approve`] with an explicit timestamp - the test hook for expiry.
    #[doc(hidden)]
    pub fn approve_at(
        &self,
        paths: Vec<PathBuf>,
        at: Instant,
        nonce: Option<String>,
    ) -> Result<Vec<ApprovedAttachment>> {
        let mut inner = self.inner.lock().unwrap();
        inner.evict_expired(at);
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            let Ok(canonical) = std::fs::canonicalize(&path) else {
                continue;
            };
            if !regular_file(&canonical) {
                continue;
            }
            if inner.approvals.len() >= MAX_APPROVALS {
                inner.evict_oldest_approval();
            }
            let filename = canonical
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "attachment".into());
            let filename = crate::display_filename(&filename);
            let mime_type = Some(crate::queue::mime_guess_from_name(&filename));
            let source = inner.source_key(&canonical);
            let token = mint_token();
            let seq = inner.next_seq;
            inner.next_seq += 1;
            let size = std::fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
            inner.approvals.insert(
                token.clone(),
                Approval {
                    canonical_path: canonical.clone(),
                    filename: filename.clone(),
                    size,
                    nonce: nonce.clone(),
                    at,
                    seq,
                },
            );
            out.push(ApprovedAttachment {
                token,
                filename,
                source,
                size,
                mime_type,
            });
        }
        Ok(out)
    }

    /// Record paths the OS reports as dropped on a window. Called only from
    /// the Rust webview-event handler - this is what makes the paths real
    /// user gestures rather than strings the webview asserts.
    pub fn record_drop(&self, paths: &[PathBuf]) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner
            .pending_drops
            .retain(|_, t| now.duration_since(*t) < DROP_TTL);
        inner
            .consumed_drops
            .retain(|_, t| now.duration_since(*t) < DROP_TTL);
        for path in paths {
            let Ok(canonical) = std::fs::canonicalize(path) else {
                continue;
            };
            while inner.pending_drops.len() >= MAX_PENDING_DROPS {
                let Some(oldest) = inner
                    .pending_drops
                    .iter()
                    .min_by_key(|(_, t)| **t)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                inner.pending_drops.remove(&oldest);
            }
            inner.pending_drops.insert(canonical, now);
        }
    }

    /// Exchange drop-event paths for approval tokens. Every path must be one
    /// this registry saw the OS drop on the window within [`DROP_TTL`] -
    /// anything else fails the whole call, so the webview cannot probe which
    /// paths are registered. Observed-but-unusable entries (directories,
    /// devices) are skipped with a reason the caller can surface, and a path
    /// whose drop was already claimed is skipped silently (the same OS drop
    /// reaching two listeners is a no-op, not an error).
    pub fn claim_drops(&self, paths: &[String], nonce: Option<String>) -> Result<DropClaim> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner.evict_expired(now);
        let mut canonical: Vec<PathBuf> = Vec::with_capacity(paths.len());
        let mut skipped: Vec<SkippedDrop> = Vec::new();
        for raw in paths {
            let canon = match std::fs::canonicalize(raw) {
                Ok(c) => c,
                Err(_) => {
                    // Might be an observed drop that vanished between drop
                    // and claim - report it if so, refuse it if not.
                    if inner
                        .pending_drops
                        .iter()
                        .any(|(p, _)| p == &PathBuf::from(raw))
                    {
                        skipped.push(SkippedDrop {
                            path: raw.clone(),
                            reason: "file no longer exists".into(),
                        });
                        continue;
                    }
                    return Err(CoreError::ActionRejected(format!(
                        "attachment {raw}: not dropped on this window"
                    )));
                }
            };
            if canonical.contains(&canon) {
                continue;
            }
            if inner.pending_drops.contains_key(&canon) {
                // A fresh OS observation wins over an older consumed marker,
                // so re-dropping the same file claims it again.
                if regular_file(&canon) {
                    canonical.push(canon);
                } else {
                    skipped.push(SkippedDrop {
                        path: raw.clone(),
                        reason: "not a file".into(),
                    });
                }
                continue;
            }
            if inner.consumed_drops.contains_key(&canon) {
                // Same drop claimed twice (double-registered listener): the
                // files are already minted for the first call's chips.
                continue;
            }
            return Err(CoreError::ActionRejected(format!(
                "attachment {raw}: not dropped on this window"
            )));
        }
        // Everything verified: consume the drop records before minting, so
        // the same OS drop can only be exchanged once.
        for c in &canonical {
            inner.pending_drops.remove(c);
            inner.consumed_drops.insert(c.clone(), now);
        }
        // Skipped-but-observed drops are also consumed - they can't become
        // claimable later.
        for s in &skipped {
            let p = PathBuf::from(&s.path);
            let canon = std::fs::canonicalize(&p).unwrap_or(p);
            inner.pending_drops.remove(&canon);
            inner.consumed_drops.insert(canon, now);
        }
        drop(inner);
        let approved = self.approve_at(canonical, now, nonce)?;
        Ok(DropClaim { approved, skipped })
    }

    /// Check out a token for a save in flight: the approval must exist, be
    /// unexpired and match the caller's composer nonce; the token is marked
    /// in-flight so a concurrent save cannot stage the same file twice.
    /// The token is consumed only by [`Self::commit`] after the draft
    /// transaction commits - [`Self::rollback`] on a failed save leaves it
    /// fully usable, so autosave retries just work.
    pub(crate) fn checkout(&self, token: &str, nonce: &Option<String>) -> Result<Approval> {
        let mut inner = self.inner.lock().unwrap();
        match inner.approvals.get(token) {
            None => Err(CoreError::ActionRejected(
                "attachment was not approved for sending; pick or drop the file again".into(),
            )),
            Some(a) if a.at.elapsed() >= APPROVAL_TTL => {
                inner.approvals.remove(token);
                Err(CoreError::ActionRejected(
                    "attachment approval expired; pick the file again".into(),
                ))
            }
            Some(a) if &a.nonce != nonce => Err(CoreError::ActionRejected(
                "attachment approval belongs to another composer session".into(),
            )),
            Some(a) => {
                if inner.in_flight.contains(token) {
                    return Err(CoreError::ActionRejected(
                        "attachment is being saved by another save".into(),
                    ));
                }
                let approval = a.clone();
                inner.in_flight.insert(token.to_string());
                Ok(approval)
            }
        }
    }

    /// Tokens whose save committed: spent for good (single-use).
    pub(crate) fn commit(&self, tokens: &[String]) {
        let mut inner = self.inner.lock().unwrap();
        for t in tokens {
            inner.approvals.remove(t);
            inner.in_flight.remove(t);
        }
    }

    /// Tokens whose save failed: usable again on the next save.
    pub(crate) fn rollback(&self, tokens: &[String]) {
        let mut inner = self.inner.lock().unwrap();
        for t in tokens {
            inner.in_flight.remove(t);
        }
    }

    /// Total source bytes of approvals bound to `nonce` that a save has not
    /// consumed yet (live + in-flight). Bounds the in-flight queue of
    /// prepared forward attachments per composer session, so a
    /// prepare->save loop cannot mint unbounded pending bytes.
    pub(crate) fn pending_bytes(&self, nonce: &Option<String>) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner
            .approvals
            .values()
            .filter(|a| &a.nonce == nonce)
            .map(|a| a.size)
            .sum()
    }

    /// Record staged paths a committed save freshly staged under `nonce`,
    /// so a draft deleted and recreated inside the same composer session
    /// can adopt them via `Staged` entries with no draft id. Callers pass
    /// only files this save copied from a token - never echoed `Staged`
    /// refs, which would let any save "produce" (and later adopt) a file
    /// some other live draft already owns. `None` nonces (internal saves)
    /// are not recorded: adoption must always be tied to a real session.
    pub(crate) fn record_produced(&self, paths: &[PathBuf], nonce: &Option<String>) {
        let Some(nonce) = nonce else { return };
        let mut inner = self.inner.lock().unwrap();
        inner.trim_produced();
        for p in paths {
            let seq = inner.next_seq;
            inner.next_seq += 1;
            inner.produced.insert(p.clone(), (nonce.clone(), seq));
        }
    }

    /// Whether this session produced (and may therefore re-claim) the staged
    /// file at `canonical_path` for a draftless save. A `None` nonce never
    /// adopts: it would let any draftless save claim any produced file.
    /// Necessary, not sufficient: `save_draft` additionally requires the
    /// database to show no live draft referencing the file, so an echoed
    /// `Staged` entry can never adopt a file another draft owns.
    pub(crate) fn produced_by(
        &self,
        canonical_path: &std::path::Path,
        nonce: &Option<String>,
    ) -> bool {
        let Some(nonce) = nonce else { return false };
        let inner = self.inner.lock().unwrap();
        inner
            .produced
            .get(canonical_path)
            .is_some_and(|(n, _)| n == nonce)
    }
}

/// Tracks tokens checked out by one `save_draft` call. Tokens are consumed
/// only via [`Self::commit`] after the draft transaction commits; dropping
/// the guard without committing - early return, panics, a dropped save
/// future - rolls every tracked token back so it can never stay marked
/// in-flight forever.
pub(crate) struct TokenGuard<'a> {
    registry: &'a AttachmentApprovals,
    tokens: Vec<String>,
    committed: bool,
}

impl<'a> TokenGuard<'a> {
    pub(crate) fn new(registry: &'a AttachmentApprovals) -> Self {
        Self {
            registry,
            tokens: Vec::new(),
            committed: false,
        }
    }

    pub(crate) fn track(&mut self, token: &str) {
        self.tokens.push(token.to_string());
    }

    /// Consume all tracked tokens (single-use semantics) and disarm the
    /// drop-time rollback.
    pub(crate) fn commit(mut self) {
        self.committed = true;
        self.registry.commit(&self.tokens);
    }
}

impl Drop for TokenGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.registry.rollback(&self.tokens);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_file(dir: &std::path::Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn expired_tokens_are_refused_on_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "f.txt");
        let old = Instant::now() - APPROVAL_TTL - Duration::from_secs(1);
        let minted = reg.approve_at(vec![f], old, None).unwrap();
        assert!(matches!(
            reg.checkout(&minted[0].token, &None),
            Err(CoreError::ActionRejected(_))
        ));
    }

    #[test]
    fn checkout_marks_in_flight_until_commit_or_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "f.txt");
        let minted = reg.approve(vec![f], None).unwrap();
        let tok = &minted[0].token;
        reg.checkout(tok, &None).unwrap();
        // A second save cannot stage the same token concurrently...
        assert!(reg.checkout(tok, &None).is_err());
        // ...but a failed save hands it back, and a committed save spends it.
        reg.rollback(std::slice::from_ref(tok));
        reg.checkout(tok, &None).unwrap();
        reg.commit(std::slice::from_ref(tok));
        assert!(reg.checkout(tok, &None).is_err());
    }

    #[test]
    fn tokens_are_bound_to_their_composer_nonce() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "f.txt");
        let minted = reg.approve(vec![f], Some("composer-a".into())).unwrap();
        let tok = &minted[0].token;
        // Wrong nonce and no nonce both fail; the right one works.
        assert!(reg.checkout(tok, &Some("composer-b".into())).is_err());
        assert!(reg.checkout(tok, &None).is_err());
        reg.checkout(tok, &Some("composer-a".into())).unwrap();
    }

    #[test]
    fn registry_cap_evicts_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let paths: Vec<PathBuf> = (0..MAX_APPROVALS + 1)
            .map(|i| tmp_file(tmp.path(), &format!("f{i}.txt")))
            .collect();
        let minted = reg.approve(paths, None).unwrap();
        assert_eq!(minted.len(), MAX_APPROVALS + 1);
        // The first pick was evicted by the (cap+1)th; the newest survives.
        assert!(reg.checkout(&minted[0].token, &None).is_err());
        assert!(reg.checkout(&minted[MAX_APPROVALS].token, &None).is_ok());
    }

    #[test]
    fn claimed_drop_cannot_be_reclaimed_but_second_claim_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "dropped.txt");
        reg.record_drop(std::slice::from_ref(&f));
        let raw = f.to_string_lossy().into_owned();
        assert_eq!(
            reg.claim_drops(std::slice::from_ref(&raw), None)
                .unwrap()
                .approved
                .len(),
            1
        );
        // A duplicate claim for the same drop no-ops instead of erroring -
        // the files were minted for the first listener.
        assert!(reg.claim_drops(&[raw], None).unwrap().approved.is_empty());
    }

    #[test]
    fn unobserved_or_non_file_paths_cannot_be_claimed() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "never-dropped.txt");
        // Real file, never recorded: the webview cannot mint it.
        assert!(matches!(
            reg.claim_drops(&[f.to_string_lossy().into_owned()], None),
            Err(CoreError::ActionRejected(_))
        ));
        // An observed directory is skipped with a reason the UI can surface,
        // not silently dropped nor a forge attempt.
        let dir = tmp.path().join("a-dir");
        std::fs::create_dir_all(&dir).unwrap();
        reg.record_drop(std::slice::from_ref(&dir));
        let claim = reg
            .claim_drops(&[dir.to_string_lossy().into_owned()], None)
            .unwrap();
        assert!(claim.approved.is_empty());
        assert_eq!(claim.skipped.len(), 1);
        assert_eq!(claim.skipped[0].reason, "not a file");
    }

    #[test]
    fn pending_bytes_tracks_unconsumed_approvals_per_nonce() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "f.txt"); // 1 byte
        let nonce = Some("session-a".to_string());
        let minted = reg.approve(vec![f], nonce.clone()).unwrap();
        assert_eq!(reg.pending_bytes(&nonce), 1);
        // Other nonces count nothing; in-flight still counts...
        assert_eq!(reg.pending_bytes(&Some("other".into())), 0);
        reg.checkout(&minted[0].token, &nonce).unwrap();
        assert_eq!(reg.pending_bytes(&nonce), 1);
        // ...and commit (consumed) frees the budget.
        reg.commit(std::slice::from_ref(&minted[0].token));
        assert_eq!(reg.pending_bytes(&nonce), 0);
    }

    #[test]
    fn dropped_token_guard_rolls_back_commit_consumes() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "f.txt");
        let minted = reg.approve(vec![f], None).unwrap();
        let tok = minted[0].token.clone();
        // A guard dropped uncommitted returns the checkout...
        {
            let mut guard = TokenGuard::new(&reg);
            reg.checkout(&tok, &None).unwrap();
            guard.track(&tok);
            drop(guard);
        }
        // ...so the same token can be checked out again by the retry.
        let mut guard = TokenGuard::new(&reg);
        reg.checkout(&tok, &None).unwrap();
        guard.track(&tok);
        guard.commit();
        assert!(reg.checkout(&tok, &None).is_err());
    }
}
