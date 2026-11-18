import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mockInvoke } from "./mock";
import { subscribeMockEvent } from "./mockEvents";
import type { ActionStateEvent, QueueSendResult } from "./types";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

it("mock emits inflight and done with the queued action identity", async () => {
  const events: ActionStateEvent[] = [];
  const off = subscribeMockEvent("action:state", (event) => events.push(event));
  const draftPromise = mockInvoke("save_draft", { args: { accountId: 1, to: [], cc: [], bcc: [], subject: "Mock send", body: "Test" } });
  await vi.advanceTimersByTimeAsync(75);
  const draft = await draftPromise as { draftId: number };
  const result = mockInvoke("queue_send", { args: { draftId: draft.draftId, sendAt: Date.now() } });
  await vi.advanceTimersByTimeAsync(75);
  const queued = await result as QueueSendResult;
  expect(events).toEqual(["inflight", "done"].map((state) => ({ actionId: queued.actionId, kind: "send", state, error: null })));
  off();
});

it("mock cancellation emits cancelled and prevents completion", async () => {
  const events: ActionStateEvent[] = [];
  const off = subscribeMockEvent("action:state", (event) => events.push(event));
  const result = mockInvoke("queue_send", { args: { draftId: -900, sendAt: Date.now() + 10000 } });
  await vi.advanceTimersByTimeAsync(75);
  const queued = await result as QueueSendResult;
  const cancelled = mockInvoke("cancel_send", { actionId: queued.actionId });
  await vi.advanceTimersByTimeAsync(11000);
  expect(await cancelled).toEqual({ cancelled: true });
  expect(events).toEqual([{ actionId: queued.actionId, kind: "send", state: "cancelled", error: null }]);
  off();
});
