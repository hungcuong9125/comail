import { afterEach, beforeEach, expect, it, vi } from "vitest";
import i18n from "../i18n";
import { useUi } from "../stores/ui";
import { handleSendState, trackSendToast } from "./sendFeedback";

beforeEach(() => {
  vi.useFakeTimers();
  useUi.setState({ toasts: [], accountOnline: {}, offline: false });
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
