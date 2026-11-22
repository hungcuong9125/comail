import { describe, expect, it, vi } from "vitest";
import { DraftSaver } from "./draftSaver";

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("DraftSaver", () => {
  it("overlapping saves create exactly one draft", async () => {
    const calls: Array<number | null> = [];
    const saver = new DraftSaver({
      save: async (draftId) => {
        calls.push(draftId);
        return 7;
      },
    });
    saver.markChanged();
    // autosave tick, Send, and a second tick all pile in while dirty
    await Promise.all([saver.saveIfDirty(), saver.flush(), saver.saveIfDirty()]);
    expect(calls).toEqual([null]);
    expect(saver.id).toBe(7);
    expect(saver.dirty).toBe(false);
  });

  it("persists edits made during a save with a follow-up save using the new id", async () => {
    const gate = deferred<number>();
    const calls: Array<number | null> = [];
    const saver = new DraftSaver({
      save: (draftId) => {
        calls.push(draftId);
        return calls.length === 1 ? gate.promise : Promise.resolve(42);
      },
    });
    saver.markChanged();
    const pending = saver.saveIfDirty();
    // Let the first save actually start, then "type" while it is in flight.
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toEqual([null]);
    saver.markChanged();
    expect(saver.dirty).toBe(true);
    gate.resolve(42);
    await pending;
    expect(calls).toEqual([null, 42]);
    expect(saver.dirty).toBe(false);
  });

  it("marks a save that completed over newer edits as not clean, then follows up", async () => {
    const gate = deferred<number>();
    const onSaved = vi.fn();
    const saver = new DraftSaver({
      save: (draftId) => (draftId === null ? gate.promise : Promise.resolve(9)),
      onSaved,
    });
    saver.markChanged();
    void saver.saveIfDirty();
    await new Promise((r) => setTimeout(r, 0));
    saver.markChanged();
    gate.resolve(9);
    await saver.idle();
    // First completion reports dirty (edits followed its snapshot); the
    // drain then persists them and reports clean.
    expect(onSaved).toHaveBeenNthCalledWith(1, 9, false);
    expect(onSaved).toHaveBeenLastCalledWith(9, true);
    expect(saver.dirty).toBe(false);
  });

  it("discard during an in-flight create still learns the new draft id", async () => {
    const gate = deferred<number>();
    const onSaved = vi.fn();
    const saver = new DraftSaver({ save: () => gate.promise, onSaved });
    saver.markChanged();
    void saver.saveIfDirty();
    saver.close();
    gate.resolve(13);
    await saver.idle();
    // Discard can now delete the draft the late save created.
    expect(saver.id).toBe(13);
    // ...and nothing reached back into component/global state after close.
    expect(onSaved).not.toHaveBeenCalled();
  });

  it("reports saves while open and stops after close", async () => {
    const onSaved = vi.fn();
    const saver = new DraftSaver({ save: async () => 5, onSaved });
    saver.markChanged();
    await saver.saveIfDirty();
    expect(onSaved).toHaveBeenCalledWith(5, true);
  });

  it("flush awaits the in-flight save and reuses its draft id", async () => {
    const gate = deferred<number>();
    const calls: Array<number | null> = [];
    const saver = new DraftSaver({
      save: (draftId) => {
        calls.push(draftId);
        return gate.promise;
      },
    });
    saver.markChanged();
    void saver.saveIfDirty();
    const flushing = saver.flush();
    gate.resolve(21);
    expect(await flushing).toBe(21);
    expect(calls).toEqual([null]);
  });

  it("surfaces save errors and retries on the next call", async () => {
    let attempt = 0;
    const saver = new DraftSaver({
      save: async () => {
        attempt += 1;
        if (attempt === 1) throw new Error("offline");
        return 3;
      },
    });
    saver.markChanged();
    await expect(saver.saveIfDirty()).rejects.toThrow("offline");
    expect(saver.dirty).toBe(true);
    await saver.saveIfDirty();
    expect(saver.id).toBe(3);
    expect(attempt).toBe(2);
  });

  it("ignores saves requested after close", async () => {
    const save = vi.fn().mockResolvedValue(1);
    const saver = new DraftSaver({ save });
    saver.close();
    saver.markChanged();
    await saver.saveIfDirty();
    expect(save).not.toHaveBeenCalled();
  });
});
