import i18n from "../i18n";
import { call } from "../ipc/commands";
import { errorMessage } from "../ipc/errors";
import type { Settings } from "../ipc/types";
import { useUi } from "../stores/ui";
import { queryClient } from "./client";

/** The ["settings"] query exactly as `useSettings` (queries/hooks.ts) defines
 *  it - same key and same fetcher, so a write waits on the real data instead
 *  of fabricating a defaults blob to persist over it. */
const settingsQuery = {
  queryKey: ["settings"],
  queryFn: () => call("get_settings", {}),
  staleTime: Infinity,
} as const;

function reportFailure(err: unknown) {
  useUi.getState().pushToast({
    kind: "error",
    message: i18n.t("settings:toast.settingsSaveFailed", {
      detail: errorMessage(err),
    }),
  });
}

async function writeSettingsPatch(patch: Partial<Settings>): Promise<boolean> {
  let cur: Settings;
  try {
    // Waits for the in-flight query or fetches when nothing is cached; a
    // merge base derived from defaults would wipe fields the patch doesn't
    // touch (AI config, signatures, rules, OAuth ids).
    cur = await queryClient.ensureQueryData<Settings>(settingsQuery);
  } catch (err) {
    // No real settings -> no write.
    reportFailure(err);
    return false;
  }
  const next: Settings = { ...cur, ...patch };
  queryClient.setQueryData(["settings"], next);
  if (patch.theme) useUi.getState().set({ theme: patch.theme });
  try {
    await call("set_settings", { settings: next });
    return true;
  } catch (err) {
    reportFailure(err);
    // A failed write must not leave the cache claiming it succeeded: restore
    // the loaded state, then reconcile against the backend.
    queryClient.setQueryData(["settings"], cur);
    void queryClient.invalidateQueries({ queryKey: ["settings"] });
    return false;
  }
}

// Writes are serialized: each runs on the state the previous one left, so two
// quick updates can't reach the backend out of order or lose each other's
// fields.
let writeQueue: Promise<unknown> = Promise.resolve();

/** Optimistic settings write: the real settings are loaded first, the patch
 *  merged in and cached, the backend write follows, rollback on error.
 *  Resolves false (with the usual error toast) when settings can't be loaded
 *  or saved. Re-exported from SettingsPanel.tsx for existing callers. */
export function updateSettings(patch: Partial<Settings>): Promise<boolean> {
  const job = writeQueue.then(() => writeSettingsPatch(patch));
  writeQueue = job.then(
    () => undefined,
    () => undefined,
  );
  return job;
}
