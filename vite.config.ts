import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import pkg from "./package.json" with { type: "json" };

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async ({ command, mode }) => {
  // Single source of truth for "this build ships the in-browser mock
  // backend": the dev server, or an explicit VITE_MOCK=1 opt-in (which also
  // covers .env files via loadEnv). Exposed as a compile-time atom so both
  // src/ipc/mockMode.ts and src/ipc/commands.ts can fold it - an imported
  // const cannot gate a dynamic import() early enough for the bundler.
  const mockBuilt = command === "serve" || loadEnv(mode, process.cwd(), "VITE_").VITE_MOCK === "1";
  return {
  plugins: [react(), tailwindcss()],

  // Keep all build output under build/ (installers are staged there too).
  build: {
    outDir: "build/dist",
    emptyOutDir: true,
  },

  // Exposed so mock/browser dev can show a version without the Tauri app API.
  define: {
    "import.meta.env.VITE_APP_VERSION": JSON.stringify(pkg.version),
    "import.meta.env.VITE_MOCK_BUILT": JSON.stringify(mockBuilt ? "1" : ""),
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
  };
});
