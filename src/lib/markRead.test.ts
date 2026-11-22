import { describe, expect, it } from "vitest";
import {
  emptyAutoMarkRead,
  markReadDispatched,
  observeThread,
  type AutoMarkRead,
} from "./markRead";

const snap = (threadId: number, unreadCount: number, messageIds: number[]) => ({
  threadId,
  unreadCount,
  messageIds,
});

describe("observeThread", () => {
  it("owes a mark when a thread opens with unread mail", () => {
    const s = observeThread(emptyAutoMarkRead, snap(1, 2, [10, 11]));
    expect(s.pending).toBe(true);
    expect(s.threadId).toBe(1);
    expect(s.suppressed).toBe(false);
  });

  it("owes nothing when the thread opens already read", () => {
    const s = observeThread(emptyAutoMarkRead, snap(1, 0, [10, 11]));
    expect(s.pending).toBe(false);
  });

  it("keeps the mark owed across identical refetches until it lands", () => {
    let s = observeThread(emptyAutoMarkRead, snap(1, 2, [10, 11]));
    // A refetch can deliver an equal payload before the optimistic patch -
    // that must not read as "user marked unread".
    s = observeThread(s, snap(1, 2, [10, 11]));
    expect(s.pending).toBe(true);
    expect(s.suppressed).toBe(false);
    // Dispatch, then the optimistic patch arrives.
    s = markReadDispatched(s);
    s = observeThread(s, snap(1, 0, [10, 11]));
    expect(s.pending).toBe(false);
  });

  it("never re-marks after the user marks the open thread unread", () => {
    let s: AutoMarkRead = observeThread(emptyAutoMarkRead, snap(1, 1, [10]));
    s = markReadDispatched(s);
    s = observeThread(s, snap(1, 0, [10]));
    // The user marks it unread: same messages, count climbs back.
    s = observeThread(s, snap(1, 1, [10]));
    expect(s.suppressed).toBe(true);
    expect(s.pending).toBe(false);
    // Refetches keep it suppressed.
    s = observeThread(s, snap(1, 1, [10]));
    expect(s.pending).toBe(false);
    // Even genuinely new mail no longer auto-marks while it stays open:
    // the user flagged the thread for later.
    s = observeThread(s, snap(1, 2, [10, 11]));
    expect(s.pending).toBe(false);
    expect(s.suppressed).toBe(true);
  });

  it("marks again when genuinely new messages arrive in the open thread", () => {
    let s = observeThread(emptyAutoMarkRead, snap(1, 0, [10]));
    s = observeThread(s, snap(1, 1, [10, 11]));
    expect(s.pending).toBe(true);
    s = markReadDispatched(s);
    s = observeThread(s, snap(1, 0, [10, 11]));
    expect(s.pending).toBe(false);
  });

  it("ignores new messages that are already read", () => {
    let s = observeThread(emptyAutoMarkRead, snap(1, 0, [10]));
    // Our own outgoing reply synced in: new id, nothing unread.
    s = observeThread(s, snap(1, 0, [10, 11]));
    expect(s.pending).toBe(false);
    expect(s.suppressed).toBe(false);
  });

  it("resets for a different thread, including past suppression", () => {
    let s = observeThread(emptyAutoMarkRead, snap(1, 1, [10]));
    s = markReadDispatched(s);
    s = observeThread(s, snap(1, 0, [10]));
    s = observeThread(s, snap(1, 1, [10]));
    expect(s.suppressed).toBe(true);
    // Switching threads starts a fresh session.
    s = observeThread(s, snap(2, 3, [20, 21]));
    expect(s.threadId).toBe(2);
    expect(s.suppressed).toBe(false);
    expect(s.pending).toBe(true);
  });
});
