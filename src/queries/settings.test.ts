import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Settings } from "../ipc/types";
import { useUi } from "../stores/ui";
import { queryClient } from "./client";

const call = vi.fn();
vi.mock("../ipc/commands", () => ({ call: (...args: unknown[]) => call(...args) }));

const { updateSettings } = await import("./settings");

/** Real backend settings with fields a defaults blob would wipe. */
const REAL = {
  theme: "carbon",
  aiBaseUrl: "https://ai.example.com",
  googleClientId: "real-google-id",
  signatureList: [{ id: "s1", accountId: 1, name: "Work" }],
  notificationTabs: [3],
} as unknown as Settings;

const savedSettings = () =>
  call.mock.calls
    .filter(([cmd]) => cmd === "set_settings")
    .map(([, args]) => (args as { settings: Settings }).settings);

beforeEach(() => {
  call.mockReset();
  queryClient.clear();
  useUi.setState(useUi.getInitialState(), true);
});

afterEach(() => queryClient.clear());

describe("updateSettings", () => {
  it("waits for the settings query and merges into the real settings", async () => {
    let resolveGet!: (s: Settings) => void;
    call.mockImplementation((cmd: string) => {
      if (cmd === "get_settings") return new Promise((r) => (resolveGet = r));
      return Promise.resolve(undefined);
    });

    const p = updateSettings({ theme: "snow" });
    // The write must wait on the fetch, not merge into defaults.
    await Promise.resolve();
    expect(savedSettings()).toHaveLength(0);

    resolveGet(REAL);
    await expect(p).resolves.toBe(true);

    const [saved] = savedSettings();
    expect(saved.theme).toBe("snow");
    expect(saved.aiBaseUrl).toBe("https://ai.example.com");
    expect(saved.googleClientId).toBe("real-google-id");
    expect(saved.signatureList).toEqual(REAL.signatureList);
  });

  it("does not write when settings cannot be loaded", async () => {
    call.mockImplementation((cmd: string) =>
      cmd === "get_settings"
        ? Promise.reject(new Error("ipc down"))
        : Promise.resolve(undefined),
    );

    await expect(updateSettings({ theme: "snow" })).resolves.toBe(false);
    expect(savedSettings()).toHaveLength(0);
    expect(useUi.getState().toasts.some((t) => t.kind === "error")).toBe(true);
  });

  it("applies two rapid updates in order, both patches surviving", async () => {
    call.mockImplementation((cmd: string) =>
      cmd === "get_settings" ? Promise.resolve(REAL) : Promise.resolve(undefined),
    );

    const p1 = updateSettings({ aiModel: "m1" });
    const p2 = updateSettings({ notificationsEnabled: false });
    await expect(p1).resolves.toBe(true);
    await expect(p2).resolves.toBe(true);

    const saved = savedSettings();
    expect(saved).toHaveLength(2);
    expect(saved[0].aiModel).toBe("m1");
    expect(saved[0].notificationsEnabled).toBe(REAL.notificationsEnabled);
    // The second write merged into the state the first one left.
    expect(saved[1].aiModel).toBe("m1");
    expect(saved[1].notificationsEnabled).toBe(false);
    expect(saved[1].googleClientId).toBe("real-google-id");
  });

  it("restores the cache instead of claiming success on a failed write", async () => {
    call.mockImplementation((cmd: string) => {
      if (cmd === "get_settings") return Promise.resolve(REAL);
      if (cmd === "set_settings") return Promise.reject(new Error("save failed"));
      return Promise.resolve(undefined);
    });

    await expect(updateSettings({ theme: "snow" })).resolves.toBe(false);
    const cached = queryClient.getQueryData<Settings>(["settings"]);
    expect(cached?.theme).toBe("carbon");
    expect(queryClient.getQueryState(["settings"])?.isInvalidated).toBe(true);
  });
});
