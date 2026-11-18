import { afterEach, beforeEach, expect, it, vi } from "vitest";
import i18n from "../i18n";
import { useUi } from "../stores/ui";
import { handleSendState, isSentBookkeepingError, isSendOutcomeUnknown, trackSendToast } from "./sendFeedback";

beforeEach(() => {
  vi.useFakeTimers();
  useUi.setState({ toasts: [], accountOnline: {}, networkAccountIds: null, offline: false });
});
afterEach(() => vi.useRealTimers());

it("reports offline only when all known accounts are offline and prunes removed accounts", () => {
  const ui = useUi.getState();
  ui.retainNetworkAccounts([1, 2]);
  ui.setAccountOnline(1, false);
  expect(useUi.getState().offline).toBe(false);
  ui.setAccountOnline(2, false);
  expect(useUi.getState().offline).toBe(true);
  ui.setAccountOnline(1, true);
  expect(useUi.getState().offline).toBe(false);
  ui.retainNetworkAccounts([2]);
  expect(useUi.getState().accountOnline).toEqual({ 2: false });
  expect(useUi.getState().offline).toBe(true);
  ui.retainNetworkAccounts([]);
  expect(useUi.getState().offline).toBe(false);
});

it("replaces sending/countdown toast only on confirmed completion and deduplicates done", () => {
  const id = useUi.getState().pushToast({ kind: "info", message: "Sending" });
  trackSendToast(101, id);
  handleSendState({ actionId: 101, kind: "send", state: "executing" });
  expect(useUi.getState().toasts[0].message).toBe("Sending");
  handleSendState({ actionId: 101, kind: "send", state: "done" });
  handleSendState({ actionId: 101, kind: "send", state: "done" });
  expect(useUi.getState().toasts.map((toast) => toast.message)).toEqual([i18n.t("compose:sent")]);
});

it.each(["failed", "paused", "cancelled"])("dismisses sending on %s without claiming success", (state) => {
  const actionId = 200 + ["failed", "paused", "cancelled"].indexOf(state);
  trackSendToast(actionId, useUi.getState().pushToast({ kind: "info", message: "Sending" }));
  handleSendState({ actionId, kind: "send", state });
  expect(useUi.getState().toasts).toEqual([]);
});

it("handles completion before the queue response and ignores other action kinds", () => {
  handleSendState({ actionId: 301, kind: "archive", state: "done" });
  expect(useUi.getState().toasts).toEqual([]);
  handleSendState({ actionId: 301, kind: "send", state: "done" });
  trackSendToast(301, useUi.getState().pushToast({ kind: "info", message: "Sending" }));
  expect(useUi.getState().toasts.map((toast) => toast.message)).toEqual([i18n.t("compose:sent")]);
});

it("waits for the account list before declaring offline", () => {
  const ui = useUi.getState();
  ui.setAccountOnline(1, false);
  expect(useUi.getState().offline).toBe(false);
  ui.retainNetworkAccounts([1, 2]);
  expect(useUi.getState().offline).toBe(false);
  ui.setAccountOnline(2, false);
  expect(useUi.getState().offline).toBe(true);
  ui.retainNetworkAccounts([]);
  ui.setAccountOnline(1, false);
  expect(useUi.getState().offline).toBe(false);
});

it("bounds instant feedback while accepting late completion", async () => {
  trackSendToast(401, useUi.getState().pushToast({ kind: "info", message: "Sending", durationMs: 120000 }), true);
  await vi.advanceTimersByTimeAsync(120000);
  expect(useUi.getState().toasts.map((t) => t.message)).toEqual([i18n.t("compose:stillSending")]);
  await vi.advanceTimersByTimeAsync(8000);
  handleSendState({ actionId: 401, kind: "send", state: "done" });
  expect(useUi.getState().toasts.map((t) => t.message)).toEqual([i18n.t("compose:sent")]);
});

it("cancels the slow-send timer on failure", async () => {
  trackSendToast(402, useUi.getState().pushToast({ kind: "info", message: "Sending" }), true);
  handleSendState({ actionId: 402, kind: "send", state: "failed" });
  await vi.advanceTimersByTimeAsync(120000);
  expect(useUi.getState().toasts).toEqual([]);
});

it("recognizes accepted SMTP with bookkeeping failure defensively", () => {
  expect(isSentBookkeepingError("SMTP: SENT, BUT LOCAL BOOKKEEPING COULD NOT BE RECORDED: disk full")).toBe(true);
  expect(isSentBookkeepingError("SMTP rejected")).toBe(false);
  expect(isSentBookkeepingError(null)).toBe(false);
});

it("recognizes ambiguous send outcomes without confusing confirmed acceptance", () => {
  expect(isSendOutcomeUnknown("send outcome unknown: the message may have been sent, check the Sent folder before resending")).toBe(true);
  expect(isSendOutcomeUnknown("SMTP: MAY HAVE BEEN SENT")).toBe(true);
  expect(isSendOutcomeUnknown(undefined)).toBe(false);
  expect(isSendOutcomeUnknown(null)).toBe(false);
  expect(isSendOutcomeUnknown("SMTP rejected")).toBe(false);
  expect(isSendOutcomeUnknown("sent, but local bookkeeping could not be recorded")).toBe(false);
  expect(isSentBookkeepingError("may have been sent")).toBe(false);
});
