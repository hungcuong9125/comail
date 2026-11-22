import { describe, expect, it } from "vitest";
import {
  addChips,
  allReady,
  applySavedRefs,
  approvedChips,
  chipFailed,
  chipResolved,
  forwardChip,
  mapSavedRefs,
  removeChip,
  restoredChip,
  toggleForwardChips,
  wireEntries,
  withoutForwardChips,
  type ComposerAttachment,
  type ForwardSource,
} from "./draftAttachments";
import type { ApprovedAttachment, DraftAttachment } from "../ipc/types";

function approved(filename: string, source: string, token = `tok-${source}`): ApprovedAttachment {
  return { token, filename, source, size: 42, mimeType: "text/plain" };
}

const staged = (p: string, f: string): DraftAttachment => ({
  kind: "staged",
  filePath: p,
  filename: f,
});

describe("approvedChips / addChips", () => {
  it("creates ready chips with token refs and stable ids", () => {
    const chips = approvedChips([approved("a.txt", "src-a")], "picked");
    expect(chips).toHaveLength(1);
    expect(chips[0].status).toBe("ready");
    expect(chips[0].ref).toEqual({ kind: "token", token: "tok-src-a" });
    expect(chips[0].origin).toEqual({ kind: "picked", source: "src-a" });
    expect(chips[0].displayName).toBe("a.txt");
  });

  it("dedupes a re-dropped file by origin source even after its ref changed", () => {
    // Simulate: chip saved once (ref is now staged), then the same file is
    // dropped again with a NEW token. Dedupe must still hit.
    const first = addChips([], approvedChips([approved("a.txt", "src-a")], "dropped"));
    const afterSave = first.chips.map((c) => ({
      ...c,
      ref: staged("/staged/1/a.txt", "a.txt"),
    }));
    const again = addChips(afterSave, approvedChips([approved("a.txt", "src-a")], "dropped"));
    expect(again.added).toHaveLength(0);
    expect(again.chips).toHaveLength(1);
  });

  it("dedupes the same file across pick and drop gestures", () => {
    // Rust gives the same `source` alias to both - the same canonical file
    // is the same attachment regardless of which gesture produced it.
    const picked = approvedChips([approved("a.txt", "src-a")], "picked");
    const dropped = approvedChips([approved("a.txt", "src-a")], "dropped");
    const r = addChips([...picked], dropped);
    expect(r.added).toHaveLength(0);
    expect(r.chips).toHaveLength(1);
  });
});

describe("forward toggle", () => {
  it("removes forward chips regardless of their current ref shape", () => {
    const fwd = forwardChip(60, "report.pdf");
    const resolved = chipResolved(fwd, approved("report.pdf", "src-f"));
    const saved = { ...resolved, ref: staged("/staged/r.pdf", "report.pdf") };
    const picked = approvedChips([approved("own.txt", "src-o")], "picked");
    const out = withoutForwardChips([...picked, saved]);
    expect(out).toHaveLength(1);
    expect(out[0].origin.kind).toBe("picked");
  });

  it("re-adding after removal does not duplicate when originals still present", () => {
    const f1 = forwardChip(60, "a.pdf");
    const r = addChips([f1], [forwardChip(60, "a.pdf")]);
    expect(r.added).toHaveLength(0);
  });

  it("forward -> save -> untick -> save -> tick -> save: refs stay spendable", () => {
    // The round-1 must-fix: the stash must hold identity, never wire refs.
    // Mirrors Composer.tsx: sources stashed once, chips prepared outside
    // save, saved refs zipped back by request order.
    const sources: ForwardSource[] = [
      { attachmentId: 60, displayName: "report.pdf", size: null },
      { attachmentId: 61, displayName: "img.png", size: null },
    ];

    // Mount: fresh attaching chips, prepared to tokens.
    let chips: ComposerAttachment[] = [];
    const first = toggleForwardChips(chips, sources, true);
    chips = first.chips;
    chips = first.toPrepare.map((c, i) =>
      chipResolved(c, approved(c.displayName, `fwd-src-${i}`, `tok-fwd-${i}`)),
    );
    expect(allReady(chips)).toBe(true);

    // First save commits: refs become staged.
    let snapshot = chips;
    let saved = [staged("/st/1/report.pdf", "report.pdf"), staged("/st/1/img.png", "img.png")];
    chips = applySavedRefs(chips, mapSavedRefs(snapshot, saved));
    expect(wireEntries(chips)).toEqual(saved);

    // Untick -> save: forward refs gone from the wire.
    chips = toggleForwardChips(chips, sources, false).chips;
    expect(wireEntries(chips)).toEqual([]);

    // Tick again -> FRESH attaching chips, prepared to NEW tokens. The old
    // refs (consumed tokens / orphaned staged paths) are never replayed.
    const readd = toggleForwardChips(chips, sources, true);
    chips = readd.chips;
    expect(readd.toPrepare).toHaveLength(2);
    expect(readd.toPrepare.every((c) => c.ref === null && c.status === "attaching")).toBe(true);
    chips = readd.toPrepare.map((c, i) =>
      chipResolved(c, approved(c.displayName, `fwd-src-${i}`, `tok-fwd2-${i}`)),
    );
    const wire = wireEntries(chips);
    expect(wire).toEqual([
      { kind: "token", token: "tok-fwd2-0" },
      { kind: "token", token: "tok-fwd2-1" },
    ]);

    // Second save commits on those fresh tokens.
    snapshot = chips;
    saved = [staged("/st/2/report.pdf", "report.pdf"), staged("/st/2/img.png", "img.png")];
    chips = applySavedRefs(chips, mapSavedRefs(snapshot, saved));
    expect(wireEntries(chips)).toEqual(saved);
    expect(allReady(chips)).toBe(true);
  });

  it("re-tick retries a previously failed chip automatically", () => {
    const sources: ForwardSource[] = [{ attachmentId: 60, displayName: "a.pdf", size: null }];
    let chips = toggleForwardChips([], sources, true).chips;
    // It stayed in the list as an error chip; user unticked, re-ticked.
    chips = toggleForwardChips(chips.map((c) => chipFailed(c, "offline")), sources, false).chips;
    const readd = toggleForwardChips(chips, sources, true);
    expect(readd.toPrepare).toHaveLength(1);
    expect(readd.toPrepare[0].status).toBe("attaching");
  });
});

describe("wireEntries + mapSavedRefs", () => {
  it("sends only ready chips' refs and skips attaching/error chips", () => {
    const ready = approvedChips([approved("a.txt", "s1")], "picked");
    const attaching = forwardChip(9, "b.pdf");
    const failed = chipFailed(forwardChip(10, "c.pdf"), "offline");
    const wire = wireEntries([...ready, attaching, failed]);
    expect(wire).toEqual([{ kind: "token", token: "tok-s1" }]);
    expect(allReady([...ready, attaching, failed])).toBe(false);
    expect(allReady(ready)).toBe(true);
  });

  it("maps save results back to chips by request order, not filename", () => {
    // Two chips with the SAME display name must still map to their own
    // request position.
    const snapshot = [
      ...approvedChips(
        [approved("same.txt", "s1", "t1"), approved("same.txt", "s2", "t2")],
        "picked",
      ),
      forwardChip(7, "still-downloading.pdf"), // excluded from request
    ];
    const wire = wireEntries(snapshot);
    expect(wire).toHaveLength(2);
    const saved = [
      staged("/staged/1/same.txt", "same.txt"),
      staged("/staged/2/same.txt", "same.txt"),
    ];
    const refs = mapSavedRefs(snapshot, saved);
    expect(refs.get(snapshot[0].id)).toEqual(saved[0]);
    expect(refs.get(snapshot[1].id)).toEqual(saved[1]);
    expect(refs.has(snapshot[2].id)).toBe(false);
  });

  it("applySavedRefs updates by id even if chips changed during the save", () => {
    const snapshot = approvedChips(
      [approved("a.txt", "s1"), approved("b.txt", "s2")],
      "picked",
    );
    const saved = [staged("/s/a.txt", "a.txt"), staged("/s/b.txt", "b.txt")];
    const refs = mapSavedRefs(snapshot, saved);
    // While the save was in flight: b was removed, a new chip was added.
    const extra = approvedChips([approved("c.txt", "s3")], "picked");
    const current = [snapshot[0], ...extra];
    const merged = applySavedRefs(current, refs);
    expect(merged[0].ref).toEqual(saved[0]);
    expect(merged[1].ref).toEqual({ kind: "token", token: "tok-s3" });
    // Removed chip is simply absent - no resurrection.
    expect(merged).toHaveLength(2);
  });
});

describe("restored + removal", () => {
  it("restored chips keep their staged ref and unique origins", () => {
    const a = restoredChip(staged("/staged/x/a.txt", "a.txt"));
    const b = restoredChip(staged("/staged/x/b.txt", "b.txt"));
    const r = addChips([a], [b]);
    expect(r.added).toHaveLength(1);
    expect(r.chips).toHaveLength(2);
    expect(a.ref).toEqual(staged("/staged/x/a.txt", "a.txt"));
  });

  it("removes by stable id", () => {
    const chips = approvedChips(
      [approved("a.txt", "s1"), approved("b.txt", "s2")],
      "picked",
    );
    const out = removeChip(chips, chips[0].id);
    expect(out).toHaveLength(1);
    expect(out[0].displayName).toBe("b.txt");
  });
});
