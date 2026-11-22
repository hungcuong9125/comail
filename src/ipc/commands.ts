import { invoke } from "@tauri-apps/api/core";
import type { Commands } from "./types";
import { MOCK_MODE } from "./mockMode";

// The mock backend (~4k lines of fixtures) is only compiled into dev-server
// and VITE_MOCK=1 builds. Both flags are compile-time constants, so a normal
// release build folds MOCK_BUILT to false and drops the dynamic import -
// and the mock chunk - from the output entirely.
const MOCK_BUILT = import.meta.env.DEV || import.meta.env.VITE_MOCK === "1";

type MockModule = typeof import("./mock");

let mockModule: Promise<MockModule> | null = null;

function loadMock(): Promise<MockModule> {
  if (!MOCK_BUILT) {
    return Promise.reject(new Error("mock backend is not included in this build"));
  }
  return (mockModule ??= import("./mock"));
}

/**
 * Typed IPC entry point. In mock mode (plain `pnpm dev` in a browser,
 * VITE_MOCK=1) calls are served from an in-memory fixture instead of Rust.
 */
export async function call<K extends keyof Commands>(
  cmd: K,
  args: Parameters<Commands[K]>[0],
): Promise<Awaited<ReturnType<Commands[K]>>> {
  if (MOCK_MODE) {
    const { mockInvoke } = await loadMock();
    return mockInvoke(cmd, args) as Promise<Awaited<ReturnType<Commands[K]>>>;
  }
  return invoke(cmd as string, args as Record<string, unknown>) as Promise<
    Awaited<ReturnType<Commands[K]>>
  >;
}
