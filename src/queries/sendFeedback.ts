import i18n from "../i18n";
import { useUi } from "../stores/ui";

const sendToasts = new Map<number, number>();
// An instant send can finish before queue_send's IPC response arrives.
const settled = new Map<number, string>();

export function trackSendToast(actionId: number, toastId: number) {
  if (settled.has(actionId)) {
    useUi.getState().dismissToast(toastId);
    return;
  }
  sendToasts.set(actionId, toastId);
}

export function handleSendState(event: { actionId: number; kind?: string; state: string }) {
  const { actionId, kind, state } = event;
  if (kind !== "send" || !["done", "failed", "paused", "cancelled"].includes(state)) return;
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
