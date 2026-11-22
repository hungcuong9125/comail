import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { ErrorBoundary } from "./components/common/ErrorBoundary";
import { queryClient } from "./queries/client";
import i18n from "./i18n";
import { MOCK_MODE } from "./ipc/mockMode";
import "./themes/app.css";

// A release build carries no mock backend, so outside the Tauri webview there
// is nothing to talk to. Fail loudly once instead of mounting the app and
// streaming rejected IPC calls into a blank screen.
const hasBackend = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
if (!hasBackend && !MOCK_MODE) {
  console.error(
    "Comail: no backend available. This build only runs inside the Comail app; " +
      "use `pnpm dev` (browser mock) or build with VITE_MOCK=1 for browser use.",
  );
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  hasBackend || MOCK_MODE ? (
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <ErrorBoundary fullScreen>
          <App />
        </ErrorBoundary>
      </QueryClientProvider>
    </React.StrictMode>
  ) : (
    <div className="flex h-full items-center justify-center bg-bg0 p-8 text-center text-ink">
      <p className="max-w-md text-sm">{i18n.t("errors:noBackend")}</p>
    </div>
  ),
);
