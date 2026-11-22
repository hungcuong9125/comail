/**
 * The composer's attachment model. Every chip has a stable client id and an
 * immutable `origin` - all composer logic (dedupe, the forward "include
 * original attachments" toggle, removal, undo-send reopen, save-result
 * mapping) keys on those, never on `ref`. `ref` is the mutable wire entry
 * the backend sees: an approval `token` before the first committed save, a
 * `staged` reference after it. This module is framework-free so the logic
 * is unit-testable; the Composer keeps a plain array of these chips in a
 * ref it updates synchronously alongside React state.
 */

import type {
  ApprovedAttachment,
  DraftAttachment,
  SavedAttachment,
} from "../ipc/types";

/** Where a chip's bytes came from. Immutable once the chip exists. */
export type AttachmentOrigin =
  /** A file the user picked in the native dialog. `source` is the opaque
   *  per-source alias Rust returned for dedupe. */
  | { kind: "picked"; source: string }
  /** A file dropped on the window. `source` as above. */
  | { kind: "dropped"; source: string }
  /** A received attachment carried into a forward, by `attachments` row id. */
  | { kind: "forward"; attachmentId: number }
  /** An attachment of a draft reopened from disk; `ref` starts staged. The
   *  staged path is its dedupe identity (same-draft staged paths are
   *  unique). */
  | { kind: "restored"; filePath: string };

export type AttachmentStatus =
  /** Has a usable `ref` - included in saves and sends. */
  | "ready"
  /** Forward download in flight - excluded from saves, blocks send. */
  | "attaching"
  /** Preparation failed (e.g. forward download offline). Excluded from
   *  saves; the chip stays visible so the user can remove or retry it. */
  | "error";

export interface ComposerAttachment {
  /** Stable client id; survives ref swaps and forward toggles. */
  id: string;
  origin: AttachmentOrigin;
  /** Display name from approval metadata, the attachment row, or the
   *  persisted draft row. */
  displayName: string;
  size: number | null;
  /** Current wire entry. Null while `status` is `attaching`/`error`. */
  ref: DraftAttachment | null;
  status: AttachmentStatus;
  error?: string;
}

let nextChipId = 0;

function chipId(): string {
  nextChipId += 1;
  return `att-${nextChipId}`;
}

/** Chips for user-approved files (picked or dropped). */
export function approvedChips(
  approved: ApprovedAttachment[],
  kind: "picked" | "dropped",
): ComposerAttachment[] {
  return approved.map((a) => ({
    id: chipId(),
    origin: kind === "picked"
      ? { kind: "picked", source: a.source }
      : { kind: "dropped", source: a.source },
    displayName: a.filename,
    size: a.size,
    ref: { kind: "token", token: a.token },
    status: "ready" as const,
  }));
}

/** The re-preparable identity of a forward source - everything a fresh
 *  `forwardChip` needs. The "include originals" stash holds THESE, never
 *  chips: a stashed chip would carry a `ref` (a consumed token, or a staged
 *  path some later save already orphaned) the wire can no longer spend. */
export interface ForwardSource {
  attachmentId: number;
  displayName: string;
  size: number | null;
}

/** A chip for an attachment row of the message being forwarded. Starts
 *  `attaching`; `prepare_forward_attachment` resolves it to a token. */
export function forwardChip(
  attachmentId: number,
  displayName: string,
  size: number | null = null,
): ComposerAttachment {
  return {
    id: chipId(),
    origin: { kind: "forward", attachmentId },
    displayName,
    size,
    ref: null,
    status: "attaching",
  };
}

/** A chip for an attachment a saved draft already references. */
export function restoredChip(att: DraftAttachment): ComposerAttachment {
  const staged = att.kind === "staged" ? att : { filePath: "", filename: "attachment" };
  return {
    id: chipId(),
    origin: { kind: "restored", filePath: staged.filePath },
    displayName: staged.filename,
    size: null,
    ref: att,
    status: "ready",
  };
}

/** The dedupe identity of an origin. `source` is already one alias per
 *  canonical file, so a file picked in the dialog and later dropped (or
 *  vice versa) is the same attachment; forward chips key on the attachment
 *  row; restored chips key on their staged path. */
export function originKey(origin: AttachmentOrigin): string {
  switch (origin.kind) {
    case "picked":
    case "dropped":
      return `file:${origin.source}`;
    case "forward":
      return `forward:${origin.attachmentId}`;
    case "restored":
      return `restored:${origin.filePath}`;
  }
}

/** Append chips, skipping any whose origin already exists in `chips` (a
 *  re-dropped file, or a forward chip re-added). Returns the new list plus
 *  the chips actually added so callers can react (e.g. toast). */
export function addChips(
  chips: ComposerAttachment[],
  incoming: ComposerAttachment[],
): { chips: ComposerAttachment[]; added: ComposerAttachment[] } {
  const seen = new Set(chips.map((c) => originKey(c.origin)));
  const added = incoming.filter((c) => !seen.has(originKey(c.origin)));
  return { chips: added.length ? [...chips, ...added] : chips, added };
}

export function removeChip(
  chips: ComposerAttachment[],
  id: string,
): ComposerAttachment[] {
  return chips.filter((c) => c.id !== id);
}

/** Remove every forward-origin chip (the toggle turning off). */
export function withoutForwardChips(
  chips: ComposerAttachment[],
): ComposerAttachment[] {
  return chips.filter((c) => c.origin.kind !== "forward");
}

/** The forward "include original attachments" toggle. Off removes every
 *  forward-origin chip; on re-adds FRESH `attaching` chips built from
 *  `sources` - never the old chips, whose refs are spent by then - and
 *  returns the added ones in `toPrepare` for the caller to run through
 *  `prepare_forward_attachment` again (a previously failed chip retries
 *  automatically this way). */
export function toggleForwardChips(
  chips: ComposerAttachment[],
  sources: ForwardSource[],
  include: boolean,
): { chips: ComposerAttachment[]; toPrepare: ComposerAttachment[] } {
  if (!include) return { chips: withoutForwardChips(chips), toPrepare: [] };
  const { chips: next, added } = addChips(
    chips,
    sources.map((s) => forwardChip(s.attachmentId, s.displayName, s.size)),
  );
  return { chips: next, toPrepare: added };
}

/** The wire entries for `save_draft`: every ready chip's ref, in chip
 *  order. `attaching`/`error` chips contribute nothing, so a failed or
 *  in-flight forward never blocks saving the draft text. */
export function wireEntries(chips: ComposerAttachment[]): DraftAttachment[] {
  return chips.flatMap((c) => (c.ref !== null ? [c.ref] : []));
}

/** Zip `save_draft`'s aligned result back onto the CURRENT chip array.
 *  `snapshot` is the chip list the request was built from; result entry i
 *  corresponds to the i-th request entry, i.e. the i-th snapshot chip with
 *  a non-null ref. A `staged` result swaps the chip's ref; a `refused`
 *  result marks that chip failed (over-limit) so it stays visible, blocks
 *  send, and contributes nothing to the next save. Chips added or removed
 *  while the save was in flight are untouched. */
export function applySaveResult(
  current: ComposerAttachment[],
  snapshot: ComposerAttachment[],
  saved: SavedAttachment[],
): ComposerAttachment[] {
  const outcomes = new Map<string, SavedAttachment>();
  let i = 0;
  for (const chip of snapshot) {
    if (chip.ref === null) continue;
    const entry = saved[i];
    if (entry !== undefined) outcomes.set(chip.id, entry);
    i += 1;
  }
  if (outcomes.size === 0) return current;
  return current.map((c) => {
    const s = outcomes.get(c.id);
    if (s === undefined) return c;
    if (s.kind === "staged") {
      const ref: DraftAttachment = {
        kind: "staged",
        filePath: s.filePath,
        filename: s.filename,
      };
      return ref === c.ref ? c : { ...c, ref };
    }
    return chipFailed(c, s.reason);
  });
}

/** A forward chip that finished preparing: token ref in, status ready. */
export function chipResolved(
  chip: ComposerAttachment,
  approved: ApprovedAttachment,
): ComposerAttachment {
  return {
    ...chip,
    displayName: approved.filename || chip.displayName,
    size: approved.size,
    ref: { kind: "token", token: approved.token },
    status: "ready",
    error: undefined,
  };
}

/** A forward chip whose preparation failed. */
export function chipFailed(
  chip: ComposerAttachment,
  error: string,
): ComposerAttachment {
  return { ...chip, ref: null, status: "error", error };
}

/** Whether every chip is ready - send is only allowed then (an attaching
 *  chip must resolve or be removed first). */
export function allReady(chips: ComposerAttachment[]): boolean {
  return chips.every((c) => c.status === "ready");
}
