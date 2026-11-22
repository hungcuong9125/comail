import { describe, expect, it } from "vitest";
import type { Settings } from "../ipc/types";
import { oauthSecretFlag, withOAuthSecretFlag } from "./oauthSecrets";

const base = {
  hasGoogleClientSecret: true,
  hasMsClientSecret: false,
  theme: "carbon",
} as unknown as Settings;

describe("oauthSecretFlag", () => {
  it("maps each provider to its presence flag", () => {
    expect(oauthSecretFlag("google")).toBe("hasGoogleClientSecret");
    expect(oauthSecretFlag("microsoft")).toBe("hasMsClientSecret");
  });
});

describe("withOAuthSecretFlag", () => {
  it("sets only the provider's flag", () => {
    const cleared = withOAuthSecretFlag(base, "google", false);
    expect(cleared.hasGoogleClientSecret).toBe(false);
    expect(cleared.hasMsClientSecret).toBe(false);
    expect(cleared.theme).toBe("carbon");

    const set = withOAuthSecretFlag(base, "microsoft", true);
    expect(set.hasMsClientSecret).toBe(true);
    expect(set.hasGoogleClientSecret).toBe(true);
    // The original object is untouched.
    expect(base.hasMsClientSecret).toBe(false);
  });
});
