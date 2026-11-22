/** What activating a link inside the sandboxed email-body iframe should do.
 *
 * The iframe document runs no scripts, so links cannot reach a browser on
 * their own; the parent intercepts every activation and applies this
 * decision:
 *  - "native":   leave the browser default alone - only for in-document
 *                `#anchor` refs, which scroll inside the iframe.
 *  - "external": preventDefault and hand the URL to the OS (default browser
 *                / mail client) via the opener plugin - exactly the set of
 *                schemes the Rust sanitiser keeps on `a[href]`.
 *  - "block":    preventDefault and do nothing. Anything else - `data:`,
 *                `cid:`, `javascript:`, relative paths, empty hrefs - must
 *                never navigate the iframe or the top-level webview. */
export type BodyLinkAction = "native" | "external" | "block";

/** Decide from the raw `href` attribute (not the resolved URL). */
export function bodyLinkAction(rawHref: string | null | undefined): BodyLinkAction {
  const href = rawHref?.trim() ?? "";
  if (!href) return "block";
  if (href.startsWith("#")) return "native";
  return /^(https?|mailto):/i.test(href) ? "external" : "block";
}
