import { describe, expect, it, vi } from "vitest";
import { DraftSaver } from "./draftSaver";

const ok = (id: number) => ({ id, payload: "" });

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
        return ok(7);
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
        return calls.length === 1 ? gate.promise.then(ok) : Promise.resolve(ok(42));
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
      save: (draftId) => (draftId === null ? gate.promise.then(ok) : Promise.resolve(ok(9))),
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
    const saver = new DraftSaver({ save: () => gate.promise.then(ok), onSaved });
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
    const saver = new DraftSaver({ save: async () => ok(5), onSaved });
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
        return gate.promise.then(ok);
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
        return ok(3);
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
    const save = vi.fn().mockResolvedValue(ok(1));
    const saver = new DraftSaver({ save });
    saver.close();
    saver.markChanged();
    await saver.saveIfDirty();
    expect(save).not.toHaveBeenCalled();
  });
});

describe("DraftSaver lifecycle", () => {
  const notFound = () => ({ code: "not_found", message: "gone" });
  const gone = (e: unknown) => (e as { code?: string }).code === "not_found";

  it("close then open restores saving (StrictMode effect re-run)", async () => {
    const save = vi.fn().mockResolvedValue(ok(7));
    const saver = new DraftSaver({ save });
    saver.close(); // cleanup of the fake unmount
    saver.open(); // setup of the remount
    saver.markChanged();
    await saver.saveIfDirty();
    expect(save).toHaveBeenCalledTimes(1);
    expect(saver.id).toBe(7);
    expect(saver.dirty).toBe(false);
  });

  it("flush creates a draft for a composer that has never saved", async () => {
    const saver = new DraftSaver({ save: async () => ok(11) });
    expect(saver.dirty).toBe(false);
    expect(await saver.flush()).toBe(11);
  });

  it("autosave still refuses to create a draft for untouched fields", async () => {
    const save = vi.fn().mockResolvedValue(ok(1));
    const saver = new DraftSaver({ save });
    await saver.saveIfDirty();
    expect(save).not.toHaveBeenCalled();
  });

  it("a save hitting 'draft gone' drops the stale id and recreates", async () => {
    const calls: Array<number | null> = [];
    let nextId = 0;
    const saver = new DraftSaver({
      save: (draftId) => {
        calls.push(draftId);
        if (draftId === 5) return Promise.reject(notFound());
        nextId = draftId === null ? (nextId === 0 ? 5 : 9) : draftId;
        return Promise.resolve(ok(nextId));
      },
      isDraftGone: gone,
    });
    saver.markChanged();
    await saver.saveIfDirty();
    expect(saver.id).toBe(5);

    saver.markChanged();
    await saver.saveIfDirty();
    // save(5) rejected NotFound -> the saver recreated with a null id.
    expect(calls).toEqual([null, 5, null]);
    expect(saver.id).toBe(9);
    expect(saver.dirty).toBe(false);
  });

  it("a 'gone' verdict on create is not retried forever", async () => {
    const save = vi.fn().mockRejectedValue(notFound());
    const saver = new DraftSaver({ save, isDraftGone: gone });
    saver.markChanged();
    await expect(saver.saveIfDirty()).rejects.toEqual(notFound());
    expect(save).toHaveBeenCalledTimes(1);
  });

  it("discard deletes the draft an in-flight create produced", async () => {
    const gate = deferred<number>();
    const deleted: number[] = [];
    const saver = new DraftSaver({ save: () => gate.promise.then(ok) });
    saver.markChanged();
    void saver.saveIfDirty();
    const pending = saver.discard(async (id) => {
      deleted.push(id);
    });
    gate.resolve(13);
    const res = await pending;
    expect(res.done).toBe(true);
    expect(deleted).toEqual([13]);
  });

  it("a discard whose delete fails re-opens the saver for later edits", async () => {
    const calls: Array<number | null> = [];
    const saver = new DraftSaver({
      save: (draftId) => {
        calls.push(draftId);
        return Promise.resolve(ok(5));
      },
    });
    saver.markChanged();
    await saver.saveIfDirty();
    const res = await saver.discard(() => Promise.reject(new Error("db locked")));
    expect(res.done).toBe(false);
    expect(saver.isClosed).toBe(false);
    // A later edit saves against the same draft id.
    saver.markChanged();
    await saver.saveIfDirty();
    expect(calls).toEqual([null, 5]);
    expect(saver.dirty).toBe(false);
  });

  it("a discard hitting 'draft gone' closes as already deleted", async () => {
    const saver = new DraftSaver({ save: async () => ok(5), isDraftGone: gone });
    saver.markChanged();
    await saver.saveIfDirty();
    const res = await saver.discard(() => Promise.reject(notFound()));
    expect(res.done).toBe(true);
    expect(saver.isClosed).toBe(true);
  });
});

describe("DraftSaver discard/send race", () => {
  it("flush returns null while a discard is in flight", async () => {
    const gate = deferred<void>();
    const saver = new DraftSaver({ save: async () => ok(5) });
    saver.markChanged();
    await saver.saveIfDirty();
    const pending = saver.discard(() => gate.promise);
    expect(saver.isDiscarding).toBe(true);
    // Send/save-and-close racing the discard must not get the doomed id.
    expect(await saver.flush()).toBeNull();
    gate.resolve();
    expect((await pending).done).toBe(true);
  });

  it("a discard rejected with a non-gone error clears the discarding flag", async () => {
    const saver = new DraftSaver({ save: async () => ok(5) });
    saver.markChanged();
    await saver.saveIfDirty();
    const res = await saver.discard(() =>
      Promise.reject({ code: "delete_rejected", message: "no trash folder" }),
    );
    expect(res.done).toBe(false);
    expect(saver.isDiscarding).toBe(false);
    expect(saver.isClosed).toBe(false);
    // ...and a later save still works against the same draft.
    saver.markChanged();
    await saver.saveIfDirty();
    expect(saver.id).toBe(5);
  });
});
