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
  | { kind: "failed"; names: string[] }
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
  /** Chips whose prepare IPC is in flight - start() never double-issues. */
  private readonly preparing = new Set<string>();
  /** Set by dispose(); while true, emits and prepare applications are
   *  no-ops and tokens that land late are released instead of applied. */
  private disposed = false;
  private started = false;
  readonly saver: DraftSaver;
  private readonly deps: ComposerDraftDeps;

  /** PURE constructor: builds the chip list only. No IPC, no emits -
   *  React StrictMode runs memo initialisers twice and discards one
   *  instance, and the discarded one must leave no trace. start() (in an
   *  effect) is where IPC begins. */
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
    if (opts.includeForwards) {
      this.chipsValue = addChips(
        this.chipsValue,
        this.forwardSources.map((s) =>
          forwardChip(s.attachmentId, s.displayName, s.size),
        ),
      ).chips;
    }

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
  }

  /** Begin IPC work: open the saver, mirror chips to the owner, and kick a
   *  prepare per attaching chip that isn't already in flight. Idempotent;
   *  a start after dispose re-arms the same instance (StrictMode's
   *  mount → cleanup → mount). */
  start(): void {
    if (this.started) return;
    this.started = true;
    this.disposed = false;
    this.saver.open();
    this.deps.onChips?.(this.chipsValue);
    for (const c of this.chipsValue) {
      if (c.status === "attaching" && !this.preparing.has(c.id)) {
        this.prepareChip(c);
      }
    }
  }

  /** Stop IPC work: close the saver and release every token this composer
   *  holds but never saved (chip refs + nothing else can mint them).
   *  Prepares that land after this point release their token instead of
   *  applying it. */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.started = false;
    this.saver.close();
    const released = this.chipsValue.flatMap((c) =>
      c.ref !== null && c.ref.kind === "token" ? [c.ref.token] : [],
    );
    if (released.length === 0) return;
    // The released tokens are dead: a restart (StrictMode remount) must
    // never save one. Forward chips re-mint on start(); a picked/dropped
    // token is the only handle to its file, so that chip must be
    // re-attached by hand.
    this.setChips((cur) =>
      cur.map((c) => {
        if (c.ref === null || c.ref.kind !== "token") return c;
        return c.origin.kind === "forward"
          ? { ...c, ref: null, status: "attaching" as const, error: undefined }
          : chipFailed(c, "the file must be re-attached");
      }),
    );
    this.releaseTokens(released);
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
    // A disposed controller still updates its model (restart correctness)
    // but never touches the component.
    if (!this.disposed) this.deps.onChips?.(next);
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

  /** Resolve one forward chip to a token OUTSIDE save_draft. A token that
   *  lands for a chip that is gone, already resolved, or behind a dispose
   *  is released instead of applied - it can never hold session bytes for
   *  a file nobody will save. */
  private prepareChip(chip: ComposerAttachment): void {
    if (chip.origin.kind !== "forward" || this.disposed) return;
    this.preparing.add(chip.id);
    const { count, bytes } = this.totals();
    void this.deps
      .call("prepare_forward_attachment", {
        attachmentId: chip.origin.attachmentId,
        composerNonce: this.deps.composerNonce,
        currentCount: count,
        currentBytes: bytes,
      })
      .then((a) => {
        this.preparing.delete(chip.id);
        const approved = a as ApprovedAttachment;
        const live = this.chipsValue.find((c) => c.id === chip.id);
        if (this.disposed || live === undefined || live.ref !== null) {
          this.releaseTokens([approved.token]);
          return;
        }
        this.setChips((cur) =>
          cur.map((c) => (c.id === chip.id ? chipResolved(c, approved) : c)),
        );
      })
      .catch((err: unknown) => {
        this.preparing.delete(chip.id);
        if (this.disposed) return;
        const detail = err instanceof Error ? err.message : String(err);
        this.setChips((cur) =>
          cur.map((c) => (c.id === chip.id ? chipFailed(c, detail) : c)),
        );
        this.deps.onChipFailed?.(chip, detail);
      });
  }

  /** Give back tokens this composer minted but will never spend. */
  private releaseTokens(tokens: string[]): void {
    if (tokens.length === 0) return;
    void this.deps
      .call("release_attachment_tokens", {
        tokens,
        composerNonce: this.deps.composerNonce,
      })
      .catch(() => {
        // Best effort: a failed release only delays budget recovery to
        // the 30-minute approval expiry.
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
   *  spent token or a stale staged ref. Unticking releases every token the
   *  removed chips held so the session's prepared-bytes cap recovers now,
   *  not at token expiry. */
  toggleForward(include: boolean): void {
    if (include) {
      const r = toggleForwardChips(this.chipsValue, this.forwardSources, true);
      this.setChips(() => r.chips);
      if (!this.disposed) {
        r.toPrepare.forEach((c) => this.prepareChip(c));
      }
      return;
    }
    const tokens = this.chipsValue.flatMap((c) =>
      c.origin.kind === "forward" && c.ref !== null && c.ref.kind === "token"
        ? [c.ref.token]
        : [],
    );
    this.setChips((cur) => toggleForwardChips(cur, this.forwardSources, false).chips);
    this.releaseTokens(tokens);
  }

  removeAttachment(id: string): void {
    const chip = this.chipsValue.find((c) => c.id === id);
    this.setChips((cur) => removeChipFrom(cur, id));
    if (chip?.ref !== null && chip?.ref.kind === "token") {
      this.releaseTokens([chip.ref.token]);
    }
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
    const blocked = (): SendOutcome | null => {
      const failed = this.chipsValue.filter((c) => c.status === "error");
      if (failed.length > 0) {
        return { kind: "failed", names: failed.map((c) => c.displayName) };
      }
      return allReady(this.chipsValue) ? null : { kind: "attaching" };
    };
    const early = blocked();
    if (early) return early;
    const gate = async (id: number): Promise<SendOutcome | null> => {
      const b = blocked();
      if (b) return b;
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
