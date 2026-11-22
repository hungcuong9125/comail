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

const SETTINGS_KEY = ["settings"];

function reportFailure(err: unknown) {
  useUi.getState().pushToast({
    kind: "error",
    message: i18n.t("settings:toast.settingsSaveFailed", {
      detail: errorMessage(err),
    }),
  });
}

/** Undo the eager theme switch, but only when it is still this patch's theme
 *  on screen - a later setTheme must not be reverted by an earlier failure. */
function rollbackTheme(patch: Partial<Settings>, prevTheme: Settings["theme"]) {
  if (patch.theme != null && useUi.getState().theme === patch.theme) {
    useUi.getState().set({ theme: prevTheme });
  }
}

// Writes are serialized: each runs on the state the previous one left, so two
// quick updates can't reach the backend out of order or lose each other's
// fields.
let writeQueue: Promise<unknown> = Promise.resolve();

async function writeSettingsPatch(
  patch: Partial<Settings>,
  prevTheme: Settings["theme"],
): Promise<boolean> {
  let cur: Settings;
  try {
    // Waits for the in-flight query or fetches when nothing is cached; a
    // merge base derived from defaults would wipe fields the patch doesn't
    // touch (AI config, signatures, rules, OAuth ids).
    cur = await queryClient.ensureQueryData<Settings>(settingsQuery);
  } catch (err) {
    // No real settings -> no write.
    reportFailure(err);
    rollbackTheme(patch, prevTheme);
    return false;
  }
  const next: Settings = { ...cur, ...patch };
  // A get_settings still in flight (the initial fetch, or an invalidation
  // from elsewhere) would otherwise resolve after our optimistic write and
  // clobber it with pre-write data.
  await queryClient.cancelQueries({ queryKey: SETTINGS_KEY });
  queryClient.setQueryData(SETTINGS_KEY, next);
  try {
    await call("set_settings", { settings: next });
    // Write back the value the backend confirmed: a refetch that raced the
    // write can't leave stale pre-patch data in the cache.
    queryClient.setQueryData(SETTINGS_KEY, next);
    return true;
  } catch (err) {
    reportFailure(err);
    // Roll the theme back to the last confirmed value, not the pre-call one:
    // an earlier failed patch may have left the UI on a theme that itself
    // was never persisted.
    rollbackTheme(patch, cur.theme);
    // A failed write must not leave the cache claiming it succeeded: restore
    // the loaded state, then reconcile against the backend - but only once
    // the queue has run, or the refetch could land on top of a later write's
    // optimistic data.
    queryClient.setQueryData(SETTINGS_KEY, cur);
    writeQueue = writeQueue.then(() =>
      queryClient.invalidateQueries({ queryKey: SETTINGS_KEY }),
    );
    return false;
  }
}

/** Optimistic settings write: the real settings are loaded first, the patch
 *  merged in and cached, the backend write follows, rollback on error.
 *  Resolves false (with the usual error toast) when settings can't be loaded
 *  or saved. Re-exported from SettingsPanel.tsx for existing callers. */
export function updateSettings(patch: Partial<Settings>): Promise<boolean> {
  // A theme patch flips the UI right away, as it did before the write queue -
  // the job rolls it back if the settings can't be loaded or saved.
  const prevTheme = useUi.getState().theme;
  if (patch.theme != null) useUi.getState().set({ theme: patch.theme });
  const job = writeQueue.then(() => writeSettingsPatch(patch, prevTheme));
  writeQueue = job.then(
    () => undefined,
    () => undefined,
  );
  return job;
}
