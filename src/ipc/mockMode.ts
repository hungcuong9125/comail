// Whether the UI should run against the in-browser mock backend
// (src/ipc/mock.ts) instead of real IPC. Kept in its own module - with no
// dependency on the fixtures - so importers don't pull ~4k lines of mock
// data into the bundle.
//
// MOCK_BUILT is a compile-time constant defined once in vite.config.ts
// (dev server, or VITE_MOCK=1) and injected as import.meta.env
// .VITE_MOCK_BUILT. In a normal release build it folds to false, so
// MOCK_MODE is false and every `if (MOCK_MODE)` branch is
// dead-code-eliminated. The runtime clause of MOCK_MODE then preserves the
// original meaning: mock only outside the Tauri webview, unless VITE_MOCK=1
// forces it on inside Tauri too.
export const MOCK_BUILT = import.meta.env.VITE_MOCK_BUILT === "1";

export const MOCK_MODE =
  MOCK_BUILT &&
  typeof window !== "undefined" &&
  (!("__TAURI_INTERNALS__" in window) || import.meta.env.VITE_MOCK === "1");
