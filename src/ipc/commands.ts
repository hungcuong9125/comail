import { invoke } from "@tauri-apps/api/core";
import type { Commands } from "./types";
import { MOCK_MODE } from "./mockMode";

type MockModule = typeof import("./mock");

let mockModule: Promise<MockModule> | null = null;

function loadMock(): Promise<MockModule> {
  // The flag is a compile-time constant (see vite.config.ts), so a normal
  // release build folds this to a dead branch and drops the dynamic import -
  // and the mock chunk - from the output entirely. It only stays reachable
  // while MOCK_MODE holds at runtime.
  if (import.meta.env.VITE_MOCK_BUILT !== "1") {
    return Promise.reject(new Error("mock backend is not included in this build"));
  }
  if (mockModule == null) {
    mockModule = import("./mock");
    // A failed chunk fetch must not poison the cache: clear it so the next
    // call retries instead of replaying the same rejection forever.
    mockModule.catch(() => {
      mockModule = null;
    });
  }
  return mockModule;
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
