/**
 * Serialized, version-aware draft saving for the composer.
 *
 * Every save path (autosave tick, Send, save-and-close, Discard) funnels
 * through one instance, so at most one `save_draft` call is ever in flight.
 * The change counter records which field snapshot each save persisted:
 * edits made while a save is in flight keep the saver dirty and are
 * persisted by the drain loop rather than silently dropped - and, crucially,
 * a second save can no longer start with `draftId: null` while the first is
 * still creating the draft (which used to leave duplicate drafts behind).
 *
 * Lifecycle: "closed" means the composer instance is gone, not merely
 * paused. It is reversible - `open()` re-arms it - because React's
 * StrictMode unmounts and remounts effects in dev while `useMemo` keeps the
 * same saver, and because Discard may need to keep the composer (and its
 * saver) alive when the delete fails. Callers only ever enter the terminal
 * closed state once the instance can no longer be used.
 */

export interface DraftSaverHooks {
  /**
   * Persist the current field snapshot. Must snapshot the fields
   * synchronously at call time - the saver captures the change version at
   * the same instant, so the callback sees exactly what the version covers.
   * Resolves with the draft id the backend returned AND the exact payload
   * it sent: the saver remembers it as `savedPayload` so `dirty` can be
   * answered by comparing the live probe against what was persisted.
   */
  save: (draftId: number | null) => Promise<{ id: number; payload: string }>;
  /**
   * After each completed save, but only while the saver is open. `clean` is
   * true when nothing changed since the persisted snapshot.
   */
  onSaved?: (draftId: number, clean: boolean) => void;
  /**
   * Whether a rejected call means the draft row is gone (deleted or sent
   * elsewhere). For a save, the saver drops the stale id and recreates the
   * draft from the current content; for a discard delete, it counts as
   * already deleted.
   */
  isDraftGone?: (err: unknown) => boolean;
  /**
   * Derives the payload a save would send RIGHT NOW, serialized the same
   * way `save` returns it. When provided, `dirty` is answered by comparing
   * this probe with the last persisted payload - the version counter
   * becomes a fast-path optimisation, not the source of truth, so a change
   * whose markChanged() was missed still saves.
   */
  probe?: () => string;
}

export class DraftSaver {
  /** Field-change counter; bumped on every edit. */
  private version = 0;
  /** Highest version proven persisted. */
  private savedVersion = 0;
  /** The exact payload the last successful save sent. Compared against
   *  `hooks.probe()` to derive dirtiness - the version counter is an
   *  optimisation, this is the ground truth. */
  private savedPayload: string | null = null;
  private draftIdValue: number | null;
  /** Serializes drains; never rejects (each `run` promise carries errors). */
  private chain: Promise<unknown> = Promise.resolve();
  private closedFlag = false;
  /** A discard is in flight: Send/save-and-close must no-op, not reuse the
   *  id that is about to be deleted. */
  private discardingFlag = false;

  constructor(
    private readonly hooks: DraftSaverHooks,
    draftId: number | null = null,
  ) {
    this.draftIdValue = draftId;
  }

  /** The id of the draft being edited (the last save's return value). */
  get id(): number | null {
    return this.draftIdValue;
  }

  /** Unpersisted changes exist: drives the unsaved indicator and Esc
   *  confirm. Derived, not remembered: the version counter answers the
   *  common case fast, and when `probe` is set, the last persisted payload
   *  is compared against what a save would send now - a change that no
   *  code path remembered to mark dirty still shows up. */
  get dirty(): boolean {
    if (this.version !== this.savedVersion) return true;
    return (
      this.savedPayload !== null &&
      this.hooks.probe !== undefined &&
      this.hooks.probe() !== this.savedPayload
    );
  }

  get isClosed(): boolean {
    return this.closedFlag;
  }

  /** Discard flow in progress: controls must not send/save against the id
   *  that is being deleted. */
  get isDiscarding(): boolean {
    return this.discardingFlag;
  }

  markChanged(): void {
    this.version += 1;
  }

  /** Autosave entry point: drain only when something changed. */
  saveIfDirty(): Promise<number | null> {
    if (this.closedFlag || !this.dirty) return Promise.resolve(this.draftIdValue);
    return this.enqueue();
  }

  /** Send / save-and-close entry point: await any in-flight save, then save
   *  again if the editor is still dirty - and create the draft when the
   *  composer has never saved, so a Send of an untouched-but-prefilled
   *  reply always has a draft to queue. Resolves with the draft id the
   *  last save produced (so a queued send always targets the one draft). */
  flush(): Promise<number | null> {
    // A discard owns the draft id now: never hand it out for a send that
    // would race the delete.
    if (this.discardingFlag) return Promise.resolve(null);
    if (this.closedFlag) return Promise.resolve(this.draftIdValue);
    return this.enqueue();
  }

  /** Stop taking saves and stop reporting them to the UI. An in-flight
   *  drain still settles so its draft id stays available via `id` (Discard
   *  needs it to delete a draft created mid-save). Reversible: `open()`
   *  re-arms the saver for a remounted effect or a discard that stayed
   *  open. */
  close(): void {
    this.closedFlag = true;
  }

  /** Re-arm after `close()`. The effect body calls this so a StrictMode
   *  cleanup (which calls `close()`) can't permanently kill the saver of a
   *  composer that is still mounted. */
  open(): void {
    this.closedFlag = false;
  }

  /**
   * Discard flow, serialized with everything else: no new saves, the
   * in-flight one settles so the draft it created can be deleted, then the
   * delete runs. The saver re-opens and resolves `done: false` when the
   * delete fails for a reason other than the draft already being gone -
   * the composer is still on screen and must keep a working saver. A
   * "draft already gone" delete counts as success.
   */
  async discard(
    deleteDraft: (id: number) => Promise<void>,
  ): Promise<{ done: boolean; error?: unknown }> {
    this.discardingFlag = true;
    this.closedFlag = true;
    await this.idle();
    const id = this.draftIdValue;
    if (id == null) return { done: true };
    try {
      await deleteDraft(id);
      return { done: true };
    } catch (error) {
      if (this.hooks.isDraftGone?.(error)) return { done: true };
      this.discardingFlag = false;
      this.closedFlag = false;
      return { done: false, error };
    }
  }

  /** Resolves once every queued save has settled. Never rejects. */
  idle(): Promise<void> {
    return this.chain.then(() => undefined);
  }

  private enqueue(): Promise<number | null> {
    const run = this.chain.then(() => this.drain());
    this.chain = run.catch(() => undefined);
    return run;
  }

  private async drain(): Promise<number | null> {
    // `draftIdValue == null` forces one save even when clean: `flush()` on a
    // never-saved composer still owes the backend a draft to queue/send.
    // `dirty` (not the raw version check) so a change detected only by the
    // payload probe still drains.
    while (this.dirty || this.draftIdValue == null) {
      const v = this.version;
      let id: number;
      try {
        const res = await this.hooks.save(this.draftIdValue);
        if (typeof res.id !== "number") {
          // A malformed save result would leave draftIdValue null and spin
          // this drain forever - fail loudly instead.
          throw new Error("save returned no draft id");
        }
        id = res.id;
        this.savedPayload = res.payload;
      } catch (err) {
        // The draft disappeared under us (deleted or sent elsewhere): drop
        // the stale id and recreate from the current content. A "gone"
        // verdict only applies while we hold an id - a failed create is a
        // real error and propagates.
        if (this.draftIdValue != null && this.hooks.isDraftGone?.(err)) {
          this.draftIdValue = null;
          continue;
        }
        throw err;
      }
      this.draftIdValue = id;
      // The snapshot covered version v; edits past it stay dirty and the
      // loop persists them next.
      this.savedVersion = Math.max(this.savedVersion, v);
      // The version counter is only a fast path: a save's own bookkeeping
      // (e.g. refs swapped for what the backend persisted) may have bumped
      // it mid-flight. If the live probe already equals the persisted
      // payload, nothing is actually unsaved - absorb the bump.
      if (
        this.hooks.probe !== undefined &&
        this.savedPayload === this.hooks.probe()
      ) {
        this.savedVersion = this.version;
      }
      if (!this.closedFlag) {
        this.hooks.onSaved?.(id, !this.dirty);
      }
    }
    return this.draftIdValue;
  }
}
