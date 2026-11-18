import i18n from "../i18n";
import { useUi } from "../stores/ui";

const sendToasts = new Map<number, number>();
// An instant send can finish before queue_send's IPC response arrives.
const settled = new Map<number, string>();

const feedbackTimers = new Map<number, ReturnType<typeof setTimeout>>();

export function isSendOutcomeUnknown(error?: string | null) {
  return error?.toLowerCase().includes("may have been sent") ?? false;
}

export function isSentBookkeepingError(error?: string | null) {
  return error?.toLowerCase().includes("sent, but local bookkeeping could not be recorded") ?? false;
}

export function trackSendToast(actionId: number, toastId: number, instant = false) {
  if (settled.has(actionId)) {
    useUi.getState().dismissToast(toastId);
    return;
  }
  sendToasts.set(actionId, toastId);
  if (instant) {
    clearTimeout(feedbackTimers.get(actionId));
    feedbackTimers.set(actionId, setTimeout(() => {
      feedbackTimers.delete(actionId);
      sendToasts.delete(actionId);
      const ui = useUi.getState();
      ui.dismissToast(toastId);
      ui.pushToast({ kind: "info", message: i18n.t("compose:stillSending"), durationMs: 8000 });
    }, 120_000));
  }
}

export function handleSendState(event: { actionId: number; kind?: string; state: string }) {
  const { actionId, kind, state } = event;
  if (kind !== "send" || !["done", "failed", "paused", "cancelled"].includes(state)) return;
  clearTimeout(feedbackTimers.get(actionId));
  feedbackTimers.delete(actionId);
  const ui = useUi.getState();
  const toastId = sendToasts.get(actionId);
  if (toastId !== undefined) ui.dismissToast(toastId);
  sendToasts.delete(actionId);
  if (state === "done" && settled.get(actionId) !== "done") {
    ui.pushToast({ kind: "info", message: i18n.t("compose:sent"), durationMs: 2500 });
  }
  settled.set(actionId, state);
  // Keep race/deduplication history bounded across a long-lived app session.
  if (settled.size > 1000) settled.delete(settled.keys().next().value!);
}
