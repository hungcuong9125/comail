import type { Settings } from "../ipc/types";

/** OAuth providers that accept a user-supplied client secret. */
export type OAuthSecretProvider = "google" | "microsoft";

/** The Settings presence flag for `provider`'s keychain-stored secret. */
export function oauthSecretFlag(
  provider: OAuthSecretProvider,
): "hasGoogleClientSecret" | "hasMsClientSecret" {
  return provider === "google"
    ? "hasGoogleClientSecret"
    : "hasMsClientSecret";
}

/** The trimmed secret a save submits, or `null` when the input is empty —
 *  an empty field must never reach `set_oauth_client_secret` (that would
 *  clear the stored secret; clearing is the separate ConfirmButton action). */
export function submittableSecret(input: string): string | null {
  const s = input.trim();
  return s === "" ? null : s;
}

/** `settings` with `provider`'s presence flag updated — the same shape
 *  `get_settings` reports after `set_oauth_client_secret`, so the cache can
 *  be patched without a refetch. */
export function withOAuthSecretFlag(
  settings: Settings,
  provider: OAuthSecretProvider,
  hasSecret: boolean,
): Settings {
  return { ...settings, [oauthSecretFlag(provider)]: hasSecret };
}
