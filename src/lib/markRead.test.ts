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

  it("re-arms once when a stale refetch lands after dispatch instead of suppressing", () => {
    let s: AutoMarkRead = observeThread(emptyAutoMarkRead, snap(1, 1, [10]));
    s = markReadDispatched(s);
    // A refetch that was already in flight returns the pre-mark payload: still
    // unread, no new messages. That is our own mark not having landed yet, not
    // the user - re-arm instead of suppressing permanently.
    s = observeThread(s, snap(1, 1, [10]));
    expect(s.suppressed).toBe(false);
    expect(s.pending).toBe(true);
    // The retry dispatches and this time the payload shows it landed.
    s = markReadDispatched(s);
    s = observeThread(s, snap(1, 0, [10]));
    expect(s.pending).toBe(false);
    expect(s.dispatched).toBe(false);
    expect(s.retried).toBe(false);
  });

  it("stops retrying when a mark keeps failing to land, without suppressing", () => {
    let s: AutoMarkRead = observeThread(emptyAutoMarkRead, snap(1, 1, [10]));
    s = markReadDispatched(s);
    // First unread payload after dispatch: stale or failed - retry once.
    s = observeThread(s, snap(1, 1, [10]));
    expect(s.pending).toBe(true);
    s = markReadDispatched(s);
    // Still unread on the next payload: stop re-arming, but do not confuse
    // this with the user marking unread either.
    s = observeThread(s, snap(1, 1, [10]));
    expect(s.pending).toBe(false);
    expect(s.dispatched).toBe(false);
    expect(s.suppressed).toBe(false);
    // Only a further identical payload now reads as a user action.
    s = observeThread(s, snap(1, 1, [10]));
    expect(s.suppressed).toBe(true);
  });

  it("holds new arrivals while a mark is in flight, then re-arms if unread stays", () => {
    let s: AutoMarkRead = observeThread(emptyAutoMarkRead, snap(1, 1, [10]));
    s = markReadDispatched(s);
    // New unread mail lands while our mark is in flight: don't stack a second
    // dispatch; the in-flight one is presumed to cover it.
    s = observeThread(s, snap(1, 2, [10, 11]));
    expect(s.pending).toBe(false);
    expect(s.dispatched).toBe(true);
    // The next payload shows it didn't: re-arm for the uncovered message.
    s = observeThread(s, snap(1, 1, [10, 11]));
    expect(s.pending).toBe(true);
  });
});
