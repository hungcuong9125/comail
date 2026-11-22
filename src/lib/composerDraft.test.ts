import { describe, expect, it, vi } from "vitest";
import { ComposerDraft, type CallFn, type DraftFields } from "./composerDraft";
import type {
  ApprovedAttachment,
  DraftAttachment,
  SaveDraftArgs,
} from "../ipc/types";

/* Scenario tests against the controller AS IT RUNS: deferred promises for
 * prepare/save, asserting the final save_draft payload and what queue_send
 * was called with. */

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** Drain pending microtasks (prepare .then callbacks, save continuations). */
const tick = () => new Promise((r) => setTimeout(r, 0));

const fields: DraftFields = {
  accountId: 1,
  to: [{ email: "a@b.c", name: null }],
  cc: [],
  bcc: [],
  subject: "hi",
  bodyText: "body",
  bodyHtml: "<p>body</p>",
  mode: "forward",
  inReplyToMessageId: 9,
};

interface Backend {
  call: CallFn;
  saves: SaveDraftArgs[];
  queues: Array<{ draftId: number; sendAt?: number; expectedAttachments?: string[] }>;
  prepares: Map<number, ReturnType<typeof deferred<ApprovedAttachment>>>;
  prepareCalls: number[];
  releases: string[][];
  prepareFor: (attachmentId: number) => ReturnType<typeof deferred<ApprovedAttachment>>;
  failNextSave: (err: unknown) => void;
}

/** A minimal in-test backend: tokens stage to deterministic paths,
 *  staged echoes pass through, prepare calls hang until the test resolves
 *  them. Mirrors the real commands' contract, nothing more. */
function makeBackend(): Backend {
  const saves: SaveDraftArgs[] = [];
  const queues: Backend["queues"] = [];
  const prepares = new Map<number, ReturnType<typeof deferred<ApprovedAttachment>>>();
  const prepareCalls: number[] = [];
  const releases: string[][] = [];
  let nextDraftId = 100;
  let failSave: unknown = null;

  const call: CallFn = async (cmd, raw) => {
    const a = (raw ?? {}) as Record<string, unknown>;
    switch (cmd) {
      case "save_draft": {
        const args = a.args as SaveDraftArgs;
        saves.push(args);
        if (failSave) {
          const e = failSave;
          failSave = null;
          throw e;
        }
        const draftId = args.draftId ?? nextDraftId++;
        return {
          draftId,
          attachments: (args.attachments ?? []).map((att: DraftAttachment) =>
            att.kind === "staged"
              ? { kind: "staged", filePath: att.filePath, filename: att.filename }
              : {
                  kind: "staged",
                  filePath: `/st/${draftId}/${att.token}`,
                  filename: `${att.token}.bin`,
                },
          ),
        };
      }
      case "queue_send":
        queues.push(a.args as Backend["queues"][number]);
        return { actionId: 7, dispatchAt: Date.now() };
      case "prepare_forward_attachment": {
        const id = a.attachmentId as number;
        prepareCalls.push(id);
        const d = deferred<ApprovedAttachment>();
        prepares.set(id, d);
        return d.promise;
      }
      case "release_attachment_tokens":
        releases.push(a.tokens as string[]);
        return undefined;
      default:
        throw new Error(`unexpected call ${cmd}`);
    }
  };
  return {
    call,
    saves,
    queues,
    prepares,
    prepareCalls,
    releases,
    prepareFor: (id) => {
      const d = prepares.get(id);
      if (!d) throw new Error(`no pending prepare for ${id}`);
      return d;
    },
    failNextSave: (err) => {
      failSave = err;
    },
  };
}

const approved = (filename: string, token: string): ApprovedAttachment => ({
  token,
  filename,
  source: `src-${token}`,
  size: 10,
  mimeType: null,
});

function makeDraft(
  backend: Backend,
  opts: ConstructorParameters<typeof ComposerDraft>[1] = {},
): ComposerDraft {
  const d = new ComposerDraft(
    {
      call: (cmd, args) => backend.call(cmd, args),
      composerNonce: "nonce-1",
      getFields: () => fields,
      isDraftGone: (err) => (err as { code?: string })?.code === "not_found",
      onChipFailed: vi.fn(),
    },
    opts,
  );
  d.start();
  return d;
}

const SOURCES = [
  { attachmentId: 60, displayName: "report.pdf", size: 10 },
  { attachmentId: 61, displayName: "img.png", size: 10 },
];

describe("ComposerDraft send orchestration", () => {
  it("(a) forward: autosave fires before prepare resolves -> send still carries the files", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: SOURCES,
      includeForwards: true,
    });
    // A body edit makes the draft dirty; the autosave tick persists the
    // text-only draft while the chips are still attaching.
    draft.saver.markChanged();
    await draft.saver.saveIfDirty();
    expect(backend.saves).toHaveLength(1);
    expect(backend.saves[0].attachments).toEqual([]);
    // Prepare resolves afterwards: the chips are ready and the draft is
    // dirty again WITHOUT any markDirty call - derived dirtiness.
    for (const [id, d] of backend.prepares) {
      d.resolve(approved(`f${id}.bin`, `tok-${id}`));
    }
    await tick();
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    // The save right before queueing carried the two tokens; queue_send
    // carried their staged paths as the expected-attachment backstop.
    const lastSave = backend.saves[backend.saves.length - 1]!;
    expect(lastSave.attachments).toHaveLength(2);
    expect(backend.queues).toHaveLength(1);
    expect(backend.queues[0].expectedAttachments?.sort()).toEqual(
      lastSave.attachments!
        .map((att: DraftAttachment) =>
          att.kind === "token"
            ? `/st/${backend.queues[0].draftId}/${att.token}`
            : att.filePath,
        )
        .sort(),
    );
  });

  it("(b) forward: autosave, untick, save, re-tick, re-prepare, send", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: SOURCES,
      includeForwards: true,
    });
    for (const [id, d] of backend.prepares) {
      d.resolve(approved(`f${id}.bin`, `tok-A-${id}`));
    }
    await tick();
    await draft.saver.flush();
    expect(backend.saves[backend.saves.length - 1]!.attachments).toHaveLength(2);
    backend.prepares.clear();

    // Untick -> forward chips gone; autosave persists the empty set.
    draft.toggleForward(false);
    await draft.saver.flush();
    expect(backend.saves[backend.saves.length - 1]!.attachments).toEqual([]);

    // Re-tick: fresh attaching chips re-run prepare (new tokens).
    draft.toggleForward(true);
    for (const [id, d] of backend.prepares) {
      d.resolve(approved(`f${id}.bin`, `tok-B-${id}`));
    }
    await tick();
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    const lastSave = backend.saves[backend.saves.length - 1]!;
    expect(lastSave.attachments).toEqual([
      { kind: "token", token: "tok-B-60" },
      { kind: "token", token: "tok-B-61" },
    ]);
    expect(backend.queues).toHaveLength(1);
    expect(backend.queues[0].expectedAttachments).toHaveLength(2);
  });

  it("(c) pick a file and press Send immediately", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend);
    const pickGate = deferred<{ approved: ApprovedAttachment[]; skipped: never[] }>();
    const orig = backend.call;
    backend.call = (cmd, args) =>
      cmd === "pick_draft_attachments" ? pickGate.promise : orig(cmd, args);
    const picking = draft.pick();
    pickGate.resolve({ approved: [approved("a.txt", "tok-a")], skipped: [] });
    await picking;
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    expect(backend.saves[backend.saves.length - 1]!.attachments).toEqual([{ kind: "token", token: "tok-a" }]);
    expect(backend.queues).toHaveLength(1);
  });

  it("(d) Send while a prepare is still running -> blocked, then sends after it resolves", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: SOURCES,
      includeForwards: true,
    });
    const blocked = await draft.send();
    expect(blocked.kind).toBe("attaching");
    expect(backend.queues).toHaveLength(0);
    for (const [id, d] of backend.prepares) {
      d.resolve(approved(`f${id}.bin`, `tok-${id}`));
    }
    await tick();
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    expect(backend.queues).toHaveLength(1);
  });

  it("(e) prepare fails -> send blocked until the chip is removed; text still autosaves", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: [SOURCES[0]],
      includeForwards: true,
    });
    backend.prepareFor(60).reject(new Error("offline"));
    await vi.waitFor(() =>
      expect(draft.chips.some((c) => c.status === "error")).toBe(true),
    );
    // The failed chip keeps send blocked with a distinct outcome naming
    // it - "remove or retry", not "still attaching".
    const blocked = await draft.send();
    expect(blocked.kind).toBe("failed");
    if (blocked.kind === "failed") {
      expect(blocked.names).toEqual(["report.pdf"]);
    }
    // ...but text still autosaves fine without it.
    draft.saver.markChanged(); // a body edit
    await draft.saver.saveIfDirty();
    expect(backend.saves[backend.saves.length - 1]!.attachments).toEqual([]);
    expect(backend.saves[backend.saves.length - 1]!.bodyText).toBe("body");
    // Removing the chip unblocks send.
    draft.removeAttachment(draft.chips[0].id);
    const out = await draft.send();
    expect(out.kind).toBe("sent");
  });

  it("(f) remove a chip then Send immediately - the draft holds nothing", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: [SOURCES[0]],
      includeForwards: true,
    });
    backend.prepareFor(60).resolve(approved("f60.bin", "tok-60"));
    await tick();
    await draft.saver.flush();
    draft.removeAttachment(draft.chips[0].id);
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    expect(backend.saves[backend.saves.length - 1]!.attachments).toEqual([]);
    expect(backend.queues[0].expectedAttachments).toEqual([]);
  });

  it("(g) undo-send reopen then Send again - staged echoes go straight to queue", async () => {
    const backend = makeBackend();
    const reopened = new ComposerDraft(
      {
        call: backend.call,
        composerNonce: "nonce-1",
        draftId: 55,
        getFields: () => fields,
      },
      {
        restored: [
          { kind: "staged", filePath: "/st/55/a.bin", filename: "a.bin" },
        ],
      },
    );
    reopened.start();
    // A reopened draft is clean: flush issues no save, the gate passes on
    // the restored set, queue_send carries the expected staged path.
    const out = await reopened.send();
    expect(out.kind).toBe("sent");
    expect(backend.saves).toHaveLength(0);
    expect(backend.queues[0].draftId).toBe(55);
    expect(backend.queues[0].expectedAttachments).toEqual(["/st/55/a.bin"]);
  });

  it("(h) save failure with a token chip, then retry succeeds", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: [SOURCES[0]],
      includeForwards: true,
    });
    backend.prepareFor(60).resolve(approved("f60.bin", "tok-60"));
    await tick();
    backend.failNextSave(new Error("offline"));
    await expect(draft.saver.flush()).rejects.toThrow("offline");
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    // The retried save re-sent the still-valid token (the first attempt
    // failed offline before staging anything).
    expect(backend.saves[backend.saves.length - 1]!.attachments).toEqual([
      { kind: "token", token: "tok-60" },
    ]);
    expect(backend.queues).toHaveLength(1);
  });

  it("(i) draft recreated after NotFound keeps its attachments", async () => {
    const backend = makeBackend();
    const draft = new ComposerDraft(
      {
        call: backend.call,
        composerNonce: "nonce-1",
        draftId: 55,
        getFields: () => fields,
        isDraftGone: (err) => (err as { code?: string })?.code === "not_found",
      },
      {
        restored: [
          { kind: "staged", filePath: "/st/55/a.bin", filename: "a.bin" },
        ],
      },
    );
    draft.start();
    // The stored id is stale: first save hits not_found and recreates.
    backend.failNextSave({ code: "not_found", message: "draft gone" });
    draft.saver.markChanged();
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    expect(backend.saves[0].draftId).toBe(55);
    expect(backend.saves[backend.saves.length - 1]!.draftId).toBe(null);
    expect(backend.saves[backend.saves.length - 1]!.attachments).toEqual([
      { kind: "staged", filePath: "/st/55/a.bin", filename: "a.bin" },
    ]);
    expect(backend.queues[0].draftId).toBe(100);
  });

  it("(j) rapid toggle of the forward checkbox settles to fresh chips", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: SOURCES,
      includeForwards: true,
    });
    draft.toggleForward(false);
    draft.toggleForward(true);
    draft.toggleForward(false);
    draft.toggleForward(true);
    // Only one fresh prepare per source survives at the end.
    for (const [id, d] of backend.prepares) {
      d.resolve(approved(`f${id}.bin`, `tok-last-${id}`));
    }
    await tick();
    const out = await draft.send();
    expect(out.kind).toBe("sent");
    expect(backend.saves[backend.saves.length - 1]!.attachments).toHaveLength(2);
  });
});

describe("ComposerDraft lifecycle + token release", () => {
  it("StrictMode: construct twice, start one; start->dispose->start issues each prepare once", async () => {
    const backend = makeBackend();
    const deps = () => ({
      call: (cmd: string, args?: unknown) => backend.call(cmd, args),
      composerNonce: "nonce-1",
      getFields: () => fields,
      onChips: vi.fn(),
    });
    // StrictMode's double memo-init: two instances, only one is started.
    const discarded = new ComposerDraft(deps(), {
      forwardSources: SOURCES,
      includeForwards: true,
    });
    const kept = new ComposerDraft(deps(), {
      forwardSources: SOURCES,
      includeForwards: true,
    });
    expect(discarded.chips).toHaveLength(2);
    kept.start();
    await tick();
    expect(backend.prepareCalls.sort()).toEqual([60, 61]);
    // mount -> cleanup -> mount on the same instance.
    kept.dispose();
    kept.start();
    await tick();
    // The prepares issued before dispose are still tracked - no re-issue.
    expect(backend.prepareCalls.sort()).toEqual([60, 61]);
    // Chips are removable on the live instance.
    kept.removeAttachment(kept.chips[0].id);
    expect(kept.chips).toHaveLength(1);
  });

  it("untick releases the chips' tokens so the session budget recovers; x10 toggles stay at one live token per attachment", async () => {
    const backend = makeBackend();
    const live = new Set<string>();
    const orig = backend.call;
    // Track live tokens: prepare mints, release returns.
    backend.call = async (cmd, args) => {
      if (cmd === "release_attachment_tokens") {
        for (const t of ((args as { tokens: string[] }).tokens ?? [])) {
          live.delete(t);
        }
        return orig(cmd, args);
      }
      const res = await orig(cmd, args);
      if (cmd === "prepare_forward_attachment") {
        // resolved later via deferreds; token lands in chipResolved
      }
      return res;
    };
    const draft = makeDraft(backend, {
      forwardSources: [SOURCES[0]],
      includeForwards: true,
    });
    for (let i = 0; i < 10; i += 1) {
      const d = backend.prepareFor(60);
      d.resolve(approved("big.bin", `tok-big-${i}`));
      await tick();
      live.add(`tok-big-${i}`);
      backend.prepares.clear();
      draft.toggleForward(false);
      draft.toggleForward(true);
    }
    // Every untick released the chip's token before the next minted.
    expect(backend.releases.flat().sort()).toEqual(
      Array.from({ length: 10 }, (_, i) => `tok-big-${i}`).sort(),
    );
    // The pending re-tick prepare resolves into exactly one live token.
    backend.prepareFor(60).resolve(approved("big.bin", "tok-big-10"));
    await tick();
    live.add("tok-big-10");
    expect(live.size).toBe(1);
    expect([...live][0]).toBe("tok-big-10");
  });

  it("dispose releases held tokens and a late prepare result is released, not applied", async () => {
    const backend = makeBackend();
    const draft = makeDraft(backend, {
      forwardSources: [SOURCES[0]],
      includeForwards: true,
    });
    // Prepare still in flight; dispose before it resolves.
    draft.dispose();
    backend.prepareFor(60).resolve(approved("f60.bin", "tok-late"));
    await tick();
    // The token was released rather than applied to a chip.
    expect(backend.releases.flat()).toContain("tok-late");
    expect(draft.chips[0].ref).toBeNull();
  });
});
