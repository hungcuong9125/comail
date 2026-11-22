//! Session registry of local files the user approved for draft attachments.
//!
//! The webview is never the authority on which local files may leave the
//! machine inside an email: a renderer that could pass any path to
//! `save_draft` (an XSS, a compromised dependency) would turn the app into an
//! arbitrary-file exfiltration channel. Approvals are therefore minted only
//! by trusted Rust paths - the native file dialog, an OS drop observed on the
//! window, or internal callers (a generated calendar invite) - and
//! `save_draft` accepts only the opaque tokens this registry hands out.
//!
//! Hardening:
//! - tokens are unguessable random strings, valid for [`APPROVAL_TTL`] and
//!   single-use (consumed by the save that stages them);
//! - the registry is capped so a misbehaving renderer cannot grow it;
//! - OS drops are registered here by Rust itself (the webview event handler
//!   observes the real drop) and expire quickly - the webview can only
//!   exchange paths Rust already saw fall on the window;
//! - the canonical path recorded at approval time is re-checked when the
//!   token is used, so a symlink swap between pick and save cannot redirect
//!   the copy.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::Result;
use crate::error::CoreError;
use crate::models::ApprovedAttachment;

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

/// Unclaimed-drop cap, same rationale as [`MAX_APPROVALS`].
const MAX_PENDING_DROPS: usize = 512;

/// A file the user approved for attaching, keyed by its opaque token.
pub(crate) struct Approval {
    /// Canonical path recorded at approval time. Re-canonicalised at use and
    /// required to match, so a symlink swapped in after the pick cannot
    /// redirect the staged copy at another file.
    pub canonical_path: PathBuf,
    /// Display filename (bidi-stripped) recorded from the approved path.
    pub filename: String,
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
    /// canonical path -> when the OS drop was observed. Paths land here only
    /// from the Rust-side webview drop handler; the webview exchanges them
    /// for tokens via `claim_drops` and may not register anything itself.
    pending_drops: HashMap<PathBuf, Instant>,
    /// Monotonic insertion counter for approval entries.
    next_seq: u64,
}

impl Inner {
    fn evict_expired(&mut self, now: Instant) {
        self.approvals
            .retain(|_, a| now.duration_since(a.at) < APPROVAL_TTL);
        self.pending_drops
            .retain(|_, t| now.duration_since(*t) < DROP_TTL);
    }

    /// Remove the oldest entry of `map` so it stays under `cap`.
    fn evict_oldest<K>(map: &mut HashMap<K, Instant>, cap: usize)
    where
        K: Clone + Eq + std::hash::Hash,
    {
        while map.len() >= cap {
            let Some(oldest) = map
                .iter()
                .max_by_key(|(_, t)| t.elapsed())
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            map.remove(&oldest);
        }
    }

    fn evict_oldest_approval(&mut self) {
        while self.approvals.len() >= MAX_APPROVALS {
            let Some(oldest) = self
                .approvals
                .iter()
                .min_by_key(|(_, a)| a.seq)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.approvals.remove(&oldest);
        }
    }
}

/// Opaque approval token: two `rand_token()`s (~103 bits) so it is
/// unguessable even for a renderer that can call `save_draft` in a loop.
fn mint_token() -> String {
    format!("{}{}", crate::mime::rand_token(), crate::mime::rand_token())
}

impl AttachmentApprovals {
    /// Mint approval tokens for user-picked local files. Callers must be
    /// trusted Rust code: the native file dialog handler, or internal code
    /// that generated the file itself (e.g. a calendar invite). Non-regular
    /// files (directories, devices, FIFOs, missing paths) are skipped.
    pub fn approve(&self, paths: Vec<PathBuf>) -> Result<Vec<ApprovedAttachment>> {
        self.approve_at(paths, Instant::now())
    }

    /// [`approve`] with an explicit timestamp - the test hook for expiry.
    #[doc(hidden)]
    pub fn approve_at(&self, paths: Vec<PathBuf>, at: Instant) -> Result<Vec<ApprovedAttachment>> {
        let mut inner = self.inner.lock().unwrap();
        inner.evict_expired(at);
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            let Ok(canonical) = std::fs::canonicalize(&path) else {
                continue;
            };
            let Ok(meta) = std::fs::metadata(&canonical) else {
                continue;
            };
            // Regular files only: a directory would fail the copy anyway, a
            // device or FIFO must never be read into an email.
            if !meta.file_type().is_file() {
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
            let token = mint_token();
            let seq = inner.next_seq;
            inner.next_seq += 1;
            inner.approvals.insert(
                token.clone(),
                Approval {
                    canonical_path: canonical.clone(),
                    filename: filename.clone(),
                    at,
                    seq,
                },
            );
            out.push(ApprovedAttachment {
                token,
                filename,
                path: canonical.to_string_lossy().into_owned(),
                size: meta.len(),
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
        for path in paths {
            let Ok(canonical) = std::fs::canonicalize(path) else {
                continue;
            };
            if inner.pending_drops.len() >= MAX_PENDING_DROPS {
                Inner::evict_oldest(&mut inner.pending_drops, MAX_PENDING_DROPS);
            }
            inner.pending_drops.insert(canonical, now);
        }
    }

    /// Exchange drop-event paths for approval tokens. Every path must be one
    /// this registry saw the OS drop on the window within [`DROP_TTL`] -
    /// anything else fails the whole call, so the webview cannot probe which
    /// paths are registered. A claimed drop is consumed; a second exchange
    /// for the same drop fails.
    pub fn claim_drops(&self, paths: &[String]) -> Result<Vec<ApprovedAttachment>> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        inner
            .pending_drops
            .retain(|_, t| now.duration_since(*t) < DROP_TTL);
        let mut canonical: Vec<PathBuf> = Vec::with_capacity(paths.len());
        for raw in paths {
            let canon = std::fs::canonicalize(raw).map_err(|_| {
                CoreError::ActionRejected(format!("attachment {raw}: not dropped on this window"))
            })?;
            if canonical.contains(&canon) {
                continue;
            }
            if !inner.pending_drops.contains_key(&canon) {
                return Err(CoreError::ActionRejected(format!(
                    "attachment {}: not dropped on this window",
                    canon.to_string_lossy()
                )));
            }
            canonical.push(canon);
        }
        // Everything verified: consume the drop records before minting, so
        // the same OS drop can only be exchanged once.
        for c in &canonical {
            inner.pending_drops.remove(c);
        }
        drop(inner);
        self.approve_at(canonical, now)
    }

    /// Consume an approval token. The token leaves the registry whether or
    /// not staging then succeeds - a token is single-purpose.
    pub(crate) fn take(&self, token: &str) -> Result<Approval> {
        let mut inner = self.inner.lock().unwrap();
        match inner.approvals.remove(token) {
            Some(a) if a.at.elapsed() < APPROVAL_TTL => Ok(a),
            Some(_) => Err(CoreError::ActionRejected(
                "attachment approval expired; pick the file again".into(),
            )),
            None => Err(CoreError::ActionRejected(
                "attachment was not approved for sending; pick or drop the file again".into(),
            )),
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
    fn expired_tokens_are_refused_on_take() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "f.txt");
        let old = Instant::now() - APPROVAL_TTL - Duration::from_secs(1);
        let minted = reg.approve_at(vec![f], old).unwrap();
        assert!(matches!(
            reg.take(&minted[0].token),
            Err(CoreError::ActionRejected(_))
        ));
    }

    #[test]
    fn registry_cap_evicts_oldest() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let paths: Vec<PathBuf> = (0..MAX_APPROVALS + 1)
            .map(|i| tmp_file(tmp.path(), &format!("f{i}.txt")))
            .collect();
        let minted = reg.approve(paths).unwrap();
        assert_eq!(minted.len(), MAX_APPROVALS + 1);
        // The first pick was evicted by the (cap+1)th; the newest survives.
        assert!(reg.take(&minted[0].token).is_err());
        assert!(reg.take(&minted[MAX_APPROVALS].token).is_ok());
    }

    #[test]
    fn claimed_drop_cannot_be_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "dropped.txt");
        reg.record_drop(std::slice::from_ref(&f));
        let raw = f.to_string_lossy().into_owned();
        assert_eq!(
            reg.claim_drops(std::slice::from_ref(&raw)).unwrap().len(),
            1
        );
        assert!(reg.claim_drops(&[raw]).is_err());
    }

    #[test]
    fn unobserved_paths_cannot_be_claimed() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = AttachmentApprovals::default();
        let f = tmp_file(tmp.path(), "never-dropped.txt");
        // Real file, never recorded: the webview cannot mint it.
        assert!(matches!(
            reg.claim_drops(&[f.to_string_lossy().into_owned()]),
            Err(CoreError::ActionRejected(_))
        ));
    }
}
