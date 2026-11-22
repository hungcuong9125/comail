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
 */

export interface DraftSaverHooks {
  /**
   * Persist the current field snapshot; resolve with the draft id the
   * backend returned. Must snapshot the fields synchronously at call time -
   * the saver captures the change version at the same instant, so the
   * callback sees exactly what the version covers.
   */
  save: (draftId: number | null) => Promise<number>;
  /**
   * After each completed save, but only while the saver is open. `clean` is
   * true when nothing changed since the persisted snapshot.
   */
  onSaved?: (draftId: number, clean: boolean) => void;
}

export class DraftSaver {
  /** Field-change counter; bumped on every edit. */
  private version = 0;
  /** Highest version proven persisted. */
  private savedVersion = 0;
  private draftIdValue: number | null;
  /** Serializes drains; never rejects (each `run` promise carries errors). */
  private chain: Promise<unknown> = Promise.resolve();
  private closedFlag = false;

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

  /** Unpersisted changes exist: drives the unsaved indicator and Esc confirm. */
  get dirty(): boolean {
    return this.version !== this.savedVersion;
  }

  get isClosed(): boolean {
    return this.closedFlag;
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
   *  again only if the editor is still dirty; resolves with the draft id the
   *  last save produced (so a queued send always targets the one draft). */
  flush(): Promise<number | null> {
    if (this.closedFlag) return Promise.resolve(this.draftIdValue);
    return this.enqueue();
  }

  /** Stop taking saves and stop reporting them to the UI. An in-flight
   *  drain still settles so its draft id stays available via `id` (Discard
   *  needs it to delete a draft created mid-save). */
  close(): void {
    this.closedFlag = true;
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
    while (this.version !== this.savedVersion) {
      const v = this.version;
      const id = await this.hooks.save(this.draftIdValue);
      this.draftIdValue = id;
      // The snapshot covered version v; edits past it stay dirty and the
      // loop persists them next.
      this.savedVersion = Math.max(this.savedVersion, v);
      if (!this.closedFlag) {
        this.hooks.onSaved?.(id, !this.dirty);
      }
    }
    return this.draftIdValue;
  }
}
