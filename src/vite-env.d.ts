/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** App version injected at build time from package.json (see vite.config.ts). */
  readonly VITE_APP_VERSION?: string;
  /** Set to "1" to force in-browser mock mode. */
  readonly VITE_MOCK?: string;
  /** "1" when this build ships the mock backend (dev server or VITE_MOCK=1); injected by vite.config.ts. */
  readonly VITE_MOCK_BUILT?: string;
}
