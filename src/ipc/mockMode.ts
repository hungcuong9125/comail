// Whether the UI should run against the in-browser mock backend
// (src/ipc/mock.ts) instead of real IPC. Kept in its own module - with no
// dependency on the fixtures - so importers don't pull ~4k lines of mock
// data into the bundle.
//
// The first clause is a compile-time constant: only dev-server builds
// (import.meta.env.DEV) and explicit VITE_MOCK=1 builds contain the mock at
// all. In a normal release build it folds to false, so MOCK_MODE is false
// and every `if (MOCK_MODE)` branch is dead-code-eliminated. The runtime
// clause then preserves the original meaning: mock only outside the Tauri
// webview, unless VITE_MOCK=1 forces it on inside Tauri too.
export const MOCK_MODE =
  (import.meta.env.DEV || import.meta.env.VITE_MOCK === "1") &&
  typeof window !== "undefined" &&
  (!("__TAURI_INTERNALS__" in window) || import.meta.env.VITE_MOCK === "1");
