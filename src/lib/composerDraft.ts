/* Composer draft controller: the attachment + save + send orchestration,
 * framework-free so the unit that runs is the unit that is tested. The
 * React component only owns field state (to/subject/body), forwards user
 * events into here, and renders `chips`.
 *
 * Owns:
 *  - the chip model (one writer, `setChips`) and the forward identity stash;
 *  - the prepare lifecycle (attaching -> ready|error, outside save_draft);
 *  - the DraftSaver and the save_draft payload (fields + wire entries);
 *  - dirtiness as a DERIVED fact: the saver's probe re-serializes the exact
 *    payload a save would send now and compares it to the last persisted
 *    one - a late chip resolution or a missed markChanged still saves;
 *  - the send gate: after flush, what the user sees (staged paths on the
 *    wire) must equal what the draft actually holds before queue_send.
 */

import type {
  Address,
  ApprovedAttachment,
  ComposeMode,
  DraftAttachment,
  DropClaim,
  QueueSendResult,
  SaveDraftResult,
} from "../ipc/types";
import { DraftSaver } from "./draftSaver";
import {
  addChips,
  allReady,
  applySaveResult,
  approvedChips,
  chipFailed,
  chipResolved,
  forwardChip,
  removeChip as removeChipFrom,
  restoredChip,
  toggleForwardChips,
  wireEntries,
  type ComposerAttachment,
  type ForwardSource,
} from "./draftAttachments";

/** The non-attachment part of a save_draft call, supplied by the owner
 *  (the component computes body text/html at call time). */
export interface DraftFields {
  accountId: number | null;
  to: Address[];
  cc: Address[];
  bcc: Address[];
  subject: string;
  bodyText: string;
  bodyHtml: string | null;
  mode: ComposeMode;
  inReplyToMessageId: number | null;
}

export type CallFn = (cmd: string, args?: unknown) => Promise<unknown>;

export interface ComposerDraftDeps {
  call: CallFn;
  composerNonce: string;
  draftId?: number | null;
  /** Current non-attachment payload, read at call time. */
  getFields: () => DraftFields;
  /** Render mirror; fires synchronously on every chip change. */
  onChips?: (chips: ComposerAttachment[]) => void;
  onSaved?: (draftId: number, clean: boolean) => void;
  isDraftGone?: (err: unknown) => boolean;
  /** A chip failed to prepare (forward download etc.) - for toasts. */
  onChipFailed?: (chip: ComposerAttachment, error: string) => void;
}

export type SendOutcome =
  | { kind: "sent"; result: QueueSendResult; draftId: number }
  | { kind: "attaching" }
  | { kind: "out_of_sync" };

/** What `send` verifies: the staged paths the LAST committed save wrote. */
function stagedWirePaths(chips: ComposerAttachment[]): string[] {
  return chips
    .map((c) => c.ref)
    .filter(
      (r): r is Extract<DraftAttachment, { kind: "staged" }> =>
        r !== null && r.kind === "staged",
    )
    .map((r) => r.filePath)
    .sort();
}

export class ComposerDraft {
  /** The synchronous source of truth for chips - never a React snapshot. */
  private chipsValue: ComposerAttachment[];
  private forwardSources: ForwardSource[] = [];
  /** Staged paths the last successful save persisted - the send gate's
   *  ground truth for "what the draft holds". */
  private savedWire: string[] = [];
  readonly saver: DraftSaver;
  private readonly deps: ComposerDraftDeps;

  constructor(
    deps: ComposerDraftDeps,
    opts: {
      restored?: DraftAttachment[];
      forwardSources?: ForwardSource[];
      includeForwards?: boolean;
    } = {},
  ) {
    this.deps = deps;
    this.chipsValue = (opts.restored ?? []).map(restoredChip);
    this.savedWire = (opts.restored ?? [])
      .filter((a): a is Extract<DraftAttachment, { kind: "staged" }> => a.kind === "staged")
      .map((a) => a.filePath)
      .sort();
    this.forwardSources = opts.forwardSources ?? [];

    this.saver = new DraftSaver(
      {
        save: (existingId) => this.runSave(existingId),
        onSaved: deps.onSaved,
        isDraftGone: deps.isDraftGone,
        // Dirtiness is the payload itself: what a save would send now vs
        // what the last save did send.
        probe: () => this.payloadString(),
      },
      deps.draftId ?? null,
    );

    if (opts.includeForwards && this.forwardSources.length > 0) {
      this.setChips((cur) =>
        addChips(
          cur,
          this.forwardSources.map((s) =>
            forwardChip(s.attachmentId, s.displayName, s.size),
          ),
        ).chips,
      );
      this.chipsValue.filter((c) => c.status === "attaching").forEach((c) => this.prepareChip(c));
    }
  }

  get chips(): ComposerAttachment[] {
    return this.chipsValue;
  }

  get dirty(): boolean {
    return this.saver.dirty;
  }

  /** The single writer. Dirtiness for attachments is derived here: the
   *  wire-relevant projection (ordered wire entries) is compared before
   *  and after, and the saver is bumped when it changed - no call site
   *  ever needs to remember markChanged for chips. */
  private setChips(fn: (cur: ComposerAttachment[]) => ComposerAttachment[]): void {
    const before = JSON.stringify(wireEntries(this.chipsValue));
    const next = fn(this.chipsValue);
    if (next === this.chipsValue) return;
    this.chipsValue = next;
    this.deps.onChips?.(next);
    if (JSON.stringify(wireEntries(next)) !== before) this.saver.markChanged();
  }

  /** The exact payload a save would send now (minus draft id/nonce - they
   *  are not user content). Compared against the last persisted payload. */
  private payloadString(): string {
    return JSON.stringify({
      ...this.deps.getFields(),
      attachments: wireEntries(this.chipsValue),
    });
  }

  /** Current draft attachment totals for mint-time limit checks. */
  private totals(): { count: number; bytes: number } {
    let count = 0;
    let bytes = 0;
    for (const c of this.chipsValue) {
      if (c.ref === null) continue;
      count += 1;
      bytes += c.size ?? 0;
    }
    return { count, bytes };
  }

  private async runSave(existingId: number | null): Promise<{ id: number; payload: string }> {
    // Snapshot the chips this request is built from; results come back
    // index-aligned to the request and are applied to the CURRENT list.
    const snapshot = this.chipsValue;
    const args = {
      draftId: existingId,
      ...this.deps.getFields(),
      attachments: wireEntries(snapshot),
      composerNonce: this.deps.composerNonce,
    };
    const result = (await this.deps.call("save_draft", { args })) as SaveDraftResult;
    this.setChips((cur) => applySaveResult(cur, snapshot, result.attachments));
    const persistedWire = result.attachments.flatMap((a) =>
      a.kind === "staged"
        ? [{ kind: "staged" as const, filePath: a.filePath, filename: a.filename }]
        : [],
    );
    this.savedWire = persistedWire.map((a) => a.filePath).sort();
    // The persisted payload is what the draft HOLDS now (staged echoes,
    // refused entries excluded) - the probe compares a future save's wire
    // against exactly this.
    const payload = JSON.stringify({
      ...this.deps.getFields(),
      attachments: persistedWire,
    });
    return { id: result.draftId, payload };
  }

  /** Resolve one forward chip to a token OUTSIDE save_draft. A late
   *  resolve lands only if the chip is still present (same id). */
  private prepareChip(chip: ComposerAttachment): void {
    if (chip.origin.kind !== "forward") return;
    const apply = (fn: (c: ComposerAttachment) => ComposerAttachment) =>
      this.setChips((cur) => cur.map((c) => (c.id === chip.id ? fn(c) : c)));
    const { count, bytes } = this.totals();
    void this.deps
      .call("prepare_forward_attachment", {
        attachmentId: chip.origin.attachmentId,
        composerNonce: this.deps.composerNonce,
        currentCount: count,
        currentBytes: bytes,
      })
      .then((a) => apply((c) => chipResolved(c, a as ApprovedAttachment)))
      .catch((err: unknown) => {
        const detail = err instanceof Error ? err.message : String(err);
        apply((c) => chipFailed(c, detail));
        this.deps.onChipFailed?.(chip, detail);
      });
  }

  /** Attach via the Rust-native picker; returns skipped entries to toast. */
  async pick(): Promise<{ path: string; reason: string }[]> {
    const { count, bytes } = this.totals();
    const claim = (await this.deps.call("pick_draft_attachments", {
      composerNonce: this.deps.composerNonce,
      currentCount: count,
      currentBytes: bytes,
    })) as DropClaim;
    if (claim.approved.length > 0) {
      this.setChips((cur) => addChips(cur, approvedChips(claim.approved, "picked")).chips);
    }
    return claim.skipped;
  }

  /** Claim OS-drop paths Rust observed; returns skipped entries to toast. */
  async claimDrops(paths: string[]): Promise<{ path: string; reason: string }[]> {
    if (paths.length === 0) return [];
    const { count, bytes } = this.totals();
    const claim = (await this.deps.call("claim_dropped_attachments", {
      paths,
      composerNonce: this.deps.composerNonce,
      currentCount: count,
      currentBytes: bytes,
    })) as DropClaim;
    if (claim.approved.length > 0) {
      this.setChips((cur) => addChips(cur, approvedChips(claim.approved, "dropped")).chips);
    }
    return claim.skipped;
  }

  /** Install the forward source identities (mount or re-tick reuses them). */
  setForwardSources(sources: ForwardSource[]): void {
    this.forwardSources = sources;
  }

  /** The include-original-attachments toggle. Identity-only stash: re-tick
   *  builds fresh attaching chips and re-runs prepare, never replays a
   *  spent token or a stale staged ref. */
  toggleForward(include: boolean): void {
    const r = toggleForwardChips(this.chipsValue, this.forwardSources, include);
    this.setChips(() => r.chips);
    if (include) r.toPrepare.forEach((c) => this.prepareChip(c));
  }

  removeAttachment(id: string): void {
    this.setChips((cur) => removeChipFrom(cur, id));
  }

  /** Current wire entries - for the undo reopen payload. */
  wire(): DraftAttachment[] {
    return wireEntries(this.chipsValue);
  }

  /** Send gate + queue. Flushes, then requires that what the user sees
   *  (chips ready + staged) is exactly what the draft holds; one
   *  resave is allowed if they differ. Only then queue_send, carrying
   *  the expected staged paths as the Rust backstop. */
  async send(opts: { sendAt?: number } = {}): Promise<SendOutcome> {
    if (!allReady(this.chipsValue)) return { kind: "attaching" };
    const gate = async (id: number): Promise<SendOutcome | null> => {
      if (!allReady(this.chipsValue)) return { kind: "attaching" };
      const wire = stagedWirePaths(this.chipsValue);
      if (wire.length !== this.savedWire.length || wire.some((p, i) => p !== this.savedWire[i])) {
        return null; // out of sync - caller may resave once
      }
      const result = (await this.deps.call("queue_send", {
        args: { draftId: id, sendAt: opts.sendAt ?? null, expectedAttachments: wire },
      })) as QueueSendResult;
      return { kind: "sent", result, draftId: id };
    };
    let id = await this.saver.flush();
    if (id === null) {
      // Saver closed under us (discard in flight) - nothing to send.
      return { kind: "out_of_sync" };
    }
    let out = await gate(id);
    if (out !== null) return out;
    // Divergence: force one resave and re-check. If still different, refuse.
    this.saver.markChanged();
    id = await this.saver.flush();
    if (id === null) return { kind: "out_of_sync" };
    out = await gate(id);
    return out ?? { kind: "out_of_sync" };
  }
}
