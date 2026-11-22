import type { ComposeMode, Settings, Signature } from "../ipc/types";
import { escapeHtml } from "./richtext";

export type { ComposeMode };

/** The signature to pre-fill for a given account and compose mode, honoring the
 *  Gmail-style defaults: `newId` for fresh mail, `replyId` for replies/forwards.
 *  Returns null when the account has no matching default configured. */
export function pickSignature(
  settings: Pick<Settings, "signatureList" | "signatureDefaults">,
  accountId: number,
  mode: ComposeMode,
): Signature | null {
  const defs = settings.signatureDefaults[String(accountId)];
  if (!defs) return null;
  const id = mode === "new" ? defs.newId : defs.replyId;
  if (!id) return null;
  return (
    settings.signatureList.find((s) => s.id === id && s.accountId === accountId) ?? null
  );
}

/** All signatures belonging to one account, in list order. */
export function signaturesForAccount(
  settings: Pick<Settings, "signatureList">,
  accountId: number,
): Signature[] {
  return settings.signatureList.filter((s) => s.accountId === accountId);
}

/** Class marking the signature block in a composed body. A class rather than a
 *  `data-` attribute: neither survives the receive-side ammonia sanitizer, but
 *  the outgoing path sends composer HTML untouched, and a class is what other
 *  clients use for the same job (Gmail's `gmail_signature`). */
export const SIGNATURE_CLASS = "co-signature";

/** Blank lines between the body text and the signature block. */
const SIGNATURE_SPACER = "<br><br>";

/** Wrap signature HTML in the block the composer can later find and swap. */
export function wrapSignature(sigHtml: string): string {
  return `<div class="${SIGNATURE_CLASS}">${sigHtml}</div>`;
}

/** [start, end) of a `<div` open tag whose class attribute lists
 *  `co-signature` (as a whitespace-separated token), or -1. Manual scan: the
 *  regex this replaced could backtrack quadratically on a `class="…` value
 *  with no closing quote. Runs on a lowercase copy so indexOf positions map
 *  straight back to the original. */
function findSigOpen(html: string): [number, number] | null {
  const lower = html.toLowerCase();
  let pos = 0;
  for (;;) {
    const lt = lower.indexOf("<div", pos);
    if (lt < 0) return null;
    const boundary = lower[lt + 4];
    if (boundary !== undefined && /[\s/>]/.test(boundary)) {
      const gt = lower.indexOf(">", lt + 4);
      if (gt < 0) return null;
      // Attributes: name [= quoted-or-bare value] pairs within [lt+4, gt).
      let i = lt + 4;
      while (i < gt) {
        while (i < gt && /[\s/]/.test(lower[i])) i += 1;
        const nameStart = i;
        while (i < gt && !/[\s/=>]/.test(lower[i])) i += 1;
        const name = lower.slice(nameStart, i);
        while (i < gt && /\s/.test(lower[i])) i += 1;
        let value = "";
        if (lower[i] === "=") {
          i += 1;
          while (i < gt && /\s/.test(lower[i])) i += 1;
          const q = lower[i];
          if (q === '"' || q === "'") {
            const close = lower.indexOf(q, i + 1);
            const vEnd = close < 0 || close > gt ? gt : close;
            value = lower.slice(i + 1, vEnd);
            i = vEnd + 1;
          } else {
            const vStart = i;
            while (i < gt && !/[\s>]/.test(lower[i])) i += 1;
            value = lower.slice(vStart, i);
          }
        }
        if (name === "class" && value.split(/\s+/).includes(SIGNATURE_CLASS)) {
          return [lt, gt + 1];
        }
      }
      pos = gt + 1;
    } else {
      pos = lt + 4;
    }
  }
}

/** [start, end) of the first signature block, matching nested <div>s by depth. */
function findSignatureBlock(html: string): [number, number] | null {
  const open = findSigOpen(html);
  if (!open) return null;
  const lower = html.toLowerCase();
  let depth = 1;
  let pos = open[1];
  for (;;) {
    const lt = lower.indexOf("<", pos);
    if (lt < 0) return [open[0], html.length];
    const closing = lower[lt + 1] === "/";
    const nameStart = lt + (closing ? 2 : 1);
    const after = lower[nameStart + 3];
    if (
      lower.startsWith("div", nameStart) &&
      (after === undefined || /[\s/>]/.test(after))
    ) {
      const gt = lower.indexOf(">", nameStart + 3);
      if (gt < 0) return [open[0], html.length];
      depth += closing ? -1 : 1;
      if (depth === 0) return [open[0], gt + 1];
      pos = gt + 1;
    } else {
      pos = lt + 1;
    }
  }
}

/** Index past the last `<br>`/whitespace run at the end of `s`, so callers can
 *  trim the spacer lines that precede a signature block. The run is found by
 *  tiling consecutive matches rather than a `(…)+$` regex, which was
 *  quadratic on a long `<br>` run not at the end. */
function trailingBrRun(s: string): number {
  const re = /<br\s*\/?>\s*/gi;
  let chainStart = -1;
  let chainEnd = -1;
  for (let m = re.exec(s); m; m = re.exec(s)) {
    if (m.index !== chainEnd) chainStart = m.index;
    chainEnd = m.index + m[0].length;
  }
  return chainEnd === s.length && chainStart >= 0 ? chainStart : s.length;
}

/** The body with its signature block removed, along with the blank lines that
 *  separated it from the text above. */
export function stripSignature(bodyHtml: string): string {
  const block = findSignatureBlock(bodyHtml);
  if (!block) return bodyHtml;
  return bodyHtml.slice(0, trailingBrRun(bodyHtml.slice(0, block[0]))) + bodyHtml.slice(block[1]);
}

/** Put `sigHtml` in as the body's signature: swaps an existing block in place
 *  (so it works after the user has typed), appends one after a spacer when
 *  there is none, and removes the block when `sigHtml` is empty. The signature
 *  is sanitized on the way in: it lands in the live composer DOM, and balanced
 *  markup keeps the block findable (an unclosed <table> would swallow the
 *  quote appended after it). */
export function replaceSignature(bodyHtml: string, sigHtml: string): string {
  const sig = sanitizeSignatureHtml(sigHtml).trim();
  if (!sig) return stripSignature(bodyHtml);
  const block = findSignatureBlock(bodyHtml);
  if (block) {
    return bodyHtml.slice(0, block[0]) + wrapSignature(sig) + bodyHtml.slice(block[1]);
  }
  return `${bodyHtml}${SIGNATURE_SPACER}${wrapSignature(sig)}`;
}

// --- Sanitizing ------------------------------------------------------------
//
// Signature HTML is user supplied (pasted from a signature generator, written
// in the editor's HTML mode, or saved by an older version) and is rendered
// live in Settings and the composer, where an `onerror` would run with the
// app's privileges. So it goes through an allowlist before it is shown, saved
// or put in a draft. The input is tokenized and the output rebuilt from
// scratch: only allowlisted tags with allowlisted, re-quoted attributes, and
// text with `<`/`>` escaped. A tokenizer that reads odd markup differently from
// a browser can therefore only drop content, never let markup through. Tags are
// balanced on output so the signature block can't leak into the body around it.
//
// The same engine, under a wider profile, sanitizes everything that enters the
// composer's contenteditable DOM (drafts, AI output, pasted HTML, inserted
// fragments) — see sanitizeEditorHtml.

/** What one sanitizing pass allows. The signature profile is the strictest;
 *  the editor profile adds the markup the composer itself produces (mention
 *  chips, the signature block's class). */
interface SanitizeProfile {
  /** Attributes kept on any allowed element. */
  globalAttrs: ReadonlySet<string>;
  /** Elements kept, with the attributes they add to globalAttrs. */
  allowed: ReadonlyMap<string, readonly string[]>;
  /** Dropped with their content, which is not markup ("<" in a script is not a
   *  tag), so they are skipped straight to their end tag. */
  rawText: ReadonlySet<string>;
  /** Dropped with everything inside them. */
  dropped: ReadonlySet<string>;
  /** Allowed URL schemes for `href`. */
  linkRe: RegExp;
  /** Allowed URL schemes for `src` / `background` / style url(). */
  imageRe: RegExp;
  /** tag -> class tokens allowed on it (class is dropped otherwise). */
  classes: ReadonlyMap<string, ReadonlySet<string>>;
  /** Inline-style property allowlist; null keeps every property not in
   *  `blockedCss`. `cssPrefixes` allows whole families ("border-"). */
  cssProps: ReadonlySet<string> | null;
  cssPrefixes: readonly string[] | null;
  /** Properties dropped when cssProps is null: `position` would let a
   *  signature cover the app around the editor; the others are legacy script
   *  hooks. */
  blockedCss: ReadonlySet<string>;
}

/** Attributes kept on any allowed element: email HTML lays signatures out with
 *  tables and presentational attributes rather than stylesheets. */
const GLOBAL_ATTRS = new Set([
  "style", "align", "valign", "width", "height", "border", "bgcolor", "color", "dir", "lang", "title",
]);

const NO_EXTRA: readonly string[] = [];

/** Elements kept, with the attributes they add to GLOBAL_ATTRS. Any other tag is
 *  unwrapped: the tag goes, its content stays (`<html>`, `<body>`, `<o:p>`). */
const ALLOWED = new Map<string, readonly string[]>([
  ...(
    "thead tbody tfoot tr caption div p span center blockquote pre address h1 h2 h3 h4 h5 h6 " +
    "br b strong i em u s strike del ins sub sup small big code tt abbr cite q mark"
  )
    .split(" ")
    .map((tag): [string, readonly string[]] => [tag, NO_EXTRA]),
  ["a", ["href", "target"]],
  ["img", ["src", "alt"]],
  ["table", ["cellpadding", "cellspacing", "background"]],
  ["td", ["colspan", "rowspan", "nowrap", "background"]],
  ["th", ["colspan", "rowspan", "nowrap", "background", "scope"]],
  ["col", ["span"]],
  ["colgroup", ["span"]],
  ["ol", ["start", "type"]],
  ["ul", ["type"]],
  ["li", ["value"]],
  ["hr", ["size", "noshade"]],
  ["font", ["face", "size"]],
]);

const VOID = new Set(["br", "hr", "img", "col"]);

/** Dropped with their content, which is not markup ("<" in a script is not a
 *  tag), so they are skipped straight to their end tag. */
const RAW_TEXT = new Set([
  "script", "style", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext",
]);

/** Dropped with everything inside them. */
const DROPPED = new Set(["template", "object", "applet", "svg", "math", "select", "audio", "video", "canvas"]);

/** Start tags that close an open <p>, as in a browser. */
const CLOSES_P = new Set([
  "address", "blockquote", "center", "div", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "li", "ol", "p", "pre",
  "table", "ul",
]);

const TABLE_PARTS = new Set(["table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup"]);
const CELL_SCOPE = new Set(["table", "td", "th", "caption"]);

/** Deepest nesting the output keeps. Past it, open tags unwrap (children
 *  stay as content) so adversarial markup can't grow the stack scan, the
 *  emitted string, or the depth the browser's own parser has to handle. */
const MAX_OPEN = 256;

/** Per-value ceilings, applied before any per-value processing so a single
 *  giant attribute can't feed unbounded work downstream. They are far above
 *  anything the editor or ordinary mail produces: the longest real styles are
 *  signature/table declarations of a few hundred bytes, mail hrefs are well
 *  under 1 KB even with tracking params, and title/alt/class text is short.
 *  Image `src`/`background` are exempt - a base64 `data:` image is
 *  legitimately megabytes and its check is a constant number of linear passes. */
const MAX_STYLE_LEN = 8 * 1024;
const MAX_DECL_LEN = 2 * 1024;
const MAX_ATTR_LEN = 4 * 1024;
const MAX_LINK_LEN = 4 * 1024;

/** Pre-compiled end-tag finders for the raw-text elements, used with exec +
 *  lastIndex so the tail is never copied per element. */
const RAW_END_RE = new Map(
  [...RAW_TEXT].map((tag) => [tag, new RegExp(`</${tag}[\\s/>]`, "gi")]),
);

/** A start or end tag, scanned manually (see scanTag). `attrs` is the raw
 *  text between the tag name and `>`; `raw` the whole `<...>` token. */
interface TagToken {
  /** Index just after the tag's `>`. */
  end: number;
  closing: boolean;
  tag: string;
  attrs: string;
  raw: string;
}

/** The tag at `src[pos]` (which must be "<"), or how to treat the "<" when no
 *  tag can start there. The tag end is found with quote awareness so a `>`
 *  inside a quoted attribute doesn't end it early. O(token length) and each
 *  source position is scanned at most once, so pathological input (thousands
 *  of unterminated `<a "` starts) stays linear where the regex this replaced
 *  was quadratic. "unterminated" reports the tail as text: a `<tag>` nested
 *  inside a malformed one was text in the old engine too, just per character. */
function scanTag(src: string, pos: number): TagToken | "literal" | "unterminated" {
  let i = pos + 1;
  const closing = src[i] === "/";
  if (closing) i += 1;
  if (!/[a-z]/i.test(src[i] ?? "")) return "literal";
  const nameStart = i;
  i += 1;
  while (i < src.length && !/[\s/>]/.test(src[i])) i += 1;
  const tag = src.slice(nameStart, i);
  const attrStart = i;
  while (i < src.length) {
    const c = src[i];
    if (c === ">") {
      return {
        end: i + 1,
        closing,
        tag,
        attrs: src.slice(attrStart, i),
        raw: src.slice(pos, i + 1),
      };
    }
    if (c === '"' || c === "'") {
      const close = src.indexOf(c, i + 1);
      if (close < 0) return "unterminated";
      i = close + 1;
    } else {
      i += 1;
    }
  }
  return "unterminated";
}

const ATTR_RE = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*)))?/g;

const SAFE_LINK = /^(?:https?|mailto|tel):/;
/** Image sources. An image (SVG included) runs no script, and the send path
 *  turns base64 `data:` images into inline parts. */
const SAFE_IMAGE = /^(?:https?:|cid:|data:image\/)/;

/** Editor links: the schemes the link tool itself will emit, plus cid: so a
 *  pasted/drafted link to an inline part survives. */
const EDITOR_LINK = /^(?:https?|mailto|tel|cid):/;
/** Editor images: raster `data:` only - `data:image/svg` carries markup. */
const EDITOR_IMAGE =
  /^(?:https?:|cid:|data:image\/(?:png|jpe?g|gif|webp|avif|bmp|x-icon|vnd\.microsoft\.icon)(?=[;,]))/;

/** Image MIME types `EDITOR_IMAGE` accepts as `data:` sources. The image
 *  tool checks files against this before reading them, so a type the
 *  allowlist would drop (SVG, TIFF, HEIC) never enters the DOM only to
 *  disappear when the draft is reopened. Keep in sync with EDITOR_IMAGE. */
export const EDITOR_IMAGE_TYPES: ReadonlySet<string> = new Set([
  "image/png", "image/jpeg", "image/gif", "image/webp", "image/avif",
  "image/bmp", "image/x-icon", "image/vnd.microsoft.icon",
]);

/** Editor styles: the presentational properties the toolbar, pasted content
 *  and signature/table markup legitimately use. Anything not listed (position,
 *  z-index, transform, visibility, content, behavior, vendor -moz-binding, …)
 *  is dropped declaration by declaration. */
const EDITOR_CSS_PROPS = new Set([
  "color", "direction", "display", "float", "clear", "hyphens", "letter-spacing",
  "line-height", "overflow-wrap", "quotes", "text-align", "text-indent",
  "text-shadow", "text-transform", "vertical-align", "white-space", "word-break",
  "word-spacing",
  "font", "font-family", "font-size", "font-style", "font-weight", "font-stretch",
  "font-size-adjust",
  "background",
  "width", "height", "min-width", "min-height", "max-width", "max-height",
  "margin", "padding", "border", "box-sizing", "outline",
  "border-collapse", "border-spacing", "caption-side", "empty-cells",
  "table-layout", "list-style",
]);
const EDITOR_CSS_PREFIXES = [
  "background-", "border-", "font-variant-", "list-style-", "margin-",
  "outline-", "padding-", "text-decoration",
];

const BLOCKED_CSS = new Set(["position", "behavior", "-moz-binding"]);

const SIGNATURE_PROFILE: SanitizeProfile = {
  globalAttrs: GLOBAL_ATTRS,
  allowed: ALLOWED,
  rawText: RAW_TEXT,
  dropped: DROPPED,
  linkRe: SAFE_LINK,
  imageRe: SAFE_IMAGE,
  classes: new Map(),
  cssProps: null,
  cssPrefixes: null,
  blockedCss: BLOCKED_CSS,
};

const EDITOR_ALLOWED = new Map<string, readonly string[]>([
  ...ALLOWED,
  // The mention chip and the signature-block wrapper are the only classes the
  // composer itself relies on (mentions.ts / findSignatureBlock).
  ["span", ["class", "contenteditable", "data-email"]],
  ["div", ["class"]],
]);

const EDITOR_PROFILE: SanitizeProfile = {
  globalAttrs: GLOBAL_ATTRS,
  allowed: EDITOR_ALLOWED,
  rawText: RAW_TEXT,
  // Only genuinely dangerous or foreign-content elements lose their content;
  // everything else unknown unwraps, keeping its children - <picture>'s img,
  // text in <form>/<button>/<dialog> chrome pasted from a page.
  dropped: DROPPED,
  linkRe: EDITOR_LINK,
  imageRe: EDITOR_IMAGE,
  classes: new Map([
    ["span", new Set(["co-mention"])],
    ["div", new Set(["co-signature"])],
  ]),
  cssProps: EDITOR_CSS_PROPS,
  cssPrefixes: EDITOR_CSS_PREFIXES,
  blockedCss: new Set(),
};

/** Character references, enough to read a URL or style the way the browser
 *  will: numeric ones, plus the named ones that spell URL and CSS punctuation
 *  (`javascript&colon;`). Any other named reference stays literal, which can
 *  only make a value fail the checks, not pass them. */
const NAMED_REFS = new Map(
  Object.entries({
    amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\xa0", Tab: "\t", NewLine: "\n",
    colon: ":", semi: ";", comma: ",", period: ".", sol: "/", bsol: "\\", lpar: "(", rpar: ")",
    excl: "!", quest: "?", num: "#", percnt: "%", plus: "+", equals: "=", commat: "@",
  }),
);

function decodeCharRefs(s: string): string {
  return s.replace(
    /&(?:#(\d+)|#x([0-9a-f]+)|([a-z]+));?/gi,
    (ref: string, dec?: string, hex?: string, name?: string) => {
      if (name !== undefined) return ref.endsWith(";") ? (NAMED_REFS.get(name) ?? ref) : ref;
      const cp = dec !== undefined ? Number(dec) : parseInt(hex ?? "", 16);
      return String.fromCodePoint(cp > 0 && cp <= 0x10ffff ? cp : 0xfffd);
    },
  );
}

function isSafeUrl(attr: string, raw: string, profile: SanitizeProfile): boolean {
  // As the URL parser reads it: references decoded, controls and spaces gone.
  // Decoding is skipped when there is no "&" so a multi-MB base64 src pays
  // only for the control-strip, lowercase and anchored test below - a
  // constant number of linear passes either way.
  const decoded = raw.includes("&") ? decodeCharRefs(raw) : raw;
  const url = decoded.replace(/[\x00-\x20\x7f-\x9f]/g, "").toLowerCase();
  return (attr === "href" ? profile.linkRe : profile.imageRe).test(url);
}

/** Split a style attribute on the `;`s between declarations (not those inside
 *  `url(data:...;base64,...)` or a quoted font name). */
function splitDeclarations(css: string): string[] {
  const out: string[] = [];
  let start = 0;
  let depth = 0;
  let quote = "";
  for (let i = 0; i < css.length; i += 1) {
    const c = css[i];
    if (quote) {
      if (c === "\\") i += 1;
      else if (c === quote) quote = "";
    } else if (c === '"' || c === "'") quote = c;
    else if (c === "(") depth += 1;
    else if (c === ")") depth = Math.max(0, depth - 1);
    else if (c === ";" && depth === 0) {
      out.push(css.slice(start, i));
      start = i + 1;
    }
  }
  out.push(css.slice(start));
  return out;
}

// CSS functions allowed inside a declaration value. image-set(), cross-fade(),
// paint(), element() and friends can carry a URL or arbitrary reference, so
// anything not on this list rejects the whole declaration.
const SAFE_CSS_FUNCS = new Set([
  "url", "rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch",
  "color", "calc", "min", "max", "clamp", "cubic-bezier", "steps", "linear",
  "counter", "counters", "attr", "local", "format",
  "linear-gradient", "radial-gradient", "conic-gradient",
  "repeating-linear-gradient", "repeating-radial-gradient", "repeating-conic-gradient",
]);

/** True when a declaration value's functions are all allowlisted and every
 *  url() points at an allowed image source. Single left-to-right scan: the
 *  `matchAll(/url\(([^)]*)\)/)` + `split("url(")` + regex function scan this
 *  replaces were quadratic on long identifiers and on unclosed `url(` runs
 *  (`url(url(url(…`). Quoted strings are skipped entirely - parens in a font
 *  name are string content, not calls. */
function checkStyleValue(value: string, profile: SanitizeProfile): boolean {
  if (/expression\s*\(|(?:java|vb)script:/.test(value)) return false;
  let i = 0;
  while (i < value.length) {
    const c = value[i];
    if (c === '"' || c === "'") {
      const close = value.indexOf(c, i + 1);
      i = close < 0 ? value.length : close + 1;
      continue;
    }
    if (c >= "a" && c <= "z") {
      const start = i;
      while (i < value.length) {
        const d = value.charCodeAt(i);
        if (!(d === 45 || (d >= 48 && d <= 57) || (d >= 97 && d <= 122))) break;
        i += 1;
      }
      const name = value.slice(start, i);
      let j = i;
      while (j < value.length && /\s/.test(value[j])) j += 1;
      if (value[j] !== "(") continue;
      if (name === "url") {
        const close = value.indexOf(")", j + 1);
        // An unclosed url( or one holding another url( rejects, as the old
        // "every url( must be a match" count check did.
        const nested = value.indexOf("url(", j + 1);
        if (close < 0 || (nested >= 0 && nested < close)) return false;
        const target = value.slice(j + 1, close).trim().replace(/^["']|["']$/g, "").trim();
        if (!profile.imageRe.test(target)) return false;
        i = close + 1;
        continue;
      }
      if (!SAFE_CSS_FUNCS.has(name)) return false;
      i = j + 1;
      continue;
    }
    i += 1;
  }
  return true;
}

/** The style's declarations minus the unsafe ones (same text otherwise). */
function cleanStyle(raw: string, profile: SanitizeProfile): string {
  return splitDeclarations(decodeCharRefs(raw))
    .filter((decl) => {
      if (decl.length > MAX_DECL_LEN) return false;
      if (!decl.trim()) return true;
      const colon = decl.indexOf(":");
      if (colon < 0) return false;
      const prop = decl.slice(0, colon).trim().toLowerCase();
      const value = decl.slice(colon + 1).toLowerCase();
      if (!/^-?[a-z][a-z0-9-]*$/.test(prop) || profile.blockedCss.has(prop)) return false;
      if (
        profile.cssProps &&
        !profile.cssProps.has(prop) &&
        !(profile.cssPrefixes ?? []).some((p) => prop.startsWith(p))
      )
        return false;
      // Escapes and comments can disguise tokens (u\72l(, u/**/rl()).
      if (value.includes("\\") || value.includes("/*")) return false;
      return checkStyleValue(value, profile);
    })
    .join(";");
}

/** Allowed attributes, re-quoted. Values keep their character references
 *  (only a quote or angle bracket is escaped), except style, rebuilt above. */
function cleanAttrs(
  raw: string,
  extra: readonly string[],
  tag: string,
  profile: SanitizeProfile,
): { attrs: string; src: boolean } {
  const seen = new Set<string>();
  const out: string[] = [];
  let src = false;
  for (const m of raw.matchAll(ATTR_RE)) {
    const name = m[1].toLowerCase();
    // A browser keeps the first of a repeated attribute.
    if (seen.has(name)) continue;
    seen.add(name);
    if (!profile.globalAttrs.has(name) && !extra.includes(name)) continue;
    let value = m[2] ?? m[3] ?? m[4] ?? "";
    if (name === "class") {
      const tokens = profile.classes.get(tag);
      if (!tokens) continue;
      if (value.length > MAX_ATTR_LEN) value = value.slice(0, MAX_ATTR_LEN);
      const kept: string[] = [];
      const dedup = new Set<string>();
      for (const tok of value.split(/\s+/)) {
        if (tokens.has(tok) && !dedup.has(tok)) {
          dedup.add(tok);
          kept.push(tok);
        }
      }
      if (kept.length) out.push(` class="${kept.join(" ")}"`);
      continue;
    }
    if (name === "contenteditable") {
      // Only the atomic mention chip needs it, and only as "false".
      if (value.trim().toLowerCase() === "false") out.push(' contenteditable="false"');
      continue;
    }
    if (name === "style") {
      if (value.length > MAX_STYLE_LEN) continue;
      const css = cleanStyle(value, profile);
      if (css.trim()) out.push(` style="${escapeHtml(css)}"`);
      continue;
    }
    // The caps apply to the escaped form: that is what a second pass reads
    // back, so the output stays a fixed point.
    const escaped = value.replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    if (name === "href") {
      if (escaped.length > MAX_LINK_LEN || !isSafeUrl(name, value, profile)) continue;
    } else if (
      (name === "src" || name === "background") &&
      !isSafeUrl(name, value, profile)
    ) {
      continue;
    }
    if (name === "src") src = true;
    out.push(` ${name}="${escaped.slice(0, MAX_ATTR_LEN)}"`);
  }
  return { attrs: out.join(""), src };
}

/** The shared tokenizer behind sanitizeSignatureHtml / sanitizeEditorHtml. */
function sanitizeWith(profile: SanitizeProfile, html: string): string {
  const src = html.replace(/\0/g, "");
  /** Open element tags, innermost last, plus per tag name the ascending stack
   *  of indexes it occupies - the tail is its innermost occurrence, so
   *  findOpen/closeNearest are O(1) and closeTo amortizes (each element is
   *  pushed once and popped once over the whole pass). */
  const open: string[] = [];
  const slots = new Map<string, number[]>();
  const parts: string[] = [];
  let pos = 0;
  /** Inside a dropped element: its tag and nesting depth. */
  let skip: { tag: string; depth: number } | null = null;

  const text = (s: string) => {
    if (!skip) parts.push(s.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
  };
  /** Index of tag's innermost open element, or -1 when none is open. */
  const topmost = (tag: string) => {
    const list = slots.get(tag);
    return list && list.length ? list[list.length - 1] : -1;
  };
  const closeTo = (i: number) => {
    while (open.length > i) {
      const tag = open.pop()!;
      slots.get(tag)!.pop();
      parts.push(`</${tag}>`);
    }
  };
  /** Close the innermost open `targets` element unless a `stops` element sits
   *  above it: the highest position among each decides, as a scan down the
   *  stack did before. */
  const closeNearest = (targets: readonly string[], stops: readonly string[]) => {
    const t = Math.max(...targets.map(topmost));
    const s = Math.max(-1, ...stops.map(topmost));
    if (t > s) closeTo(t);
  };
  /** The open element an end tag closes, or -1 to ignore it. As in a browser,
   *  an end tag doesn't reach out of the cell (table parts: the table) it is
   *  in - a boundary element above the candidate blocks the match. */
  const findOpen = (tag: string): number => {
    const i = topmost(tag);
    if (i < 0 || tag === "table") return i;
    if (TABLE_PARTS.has(tag)) return topmost("table") > i ? -1 : i;
    return Math.max(...[...CELL_SCOPE].map(topmost)) > i ? -1 : i;
  };

  while (pos < src.length) {
    const lt = src.indexOf("<", pos);
    if (lt < 0) {
      text(src.slice(pos));
      pos = src.length;
      break;
    }
    text(src.slice(pos, lt));
    const next = src[lt + 1];
    // Comments, doctype/CDATA and <?pi> are dropped (comments run to --> or
    // end of input, the rest to the first ">").
    if (next === "!") {
      const isComment = src.startsWith("<!--", lt);
      const end = isComment ? src.indexOf("-->", lt + 4) : src.indexOf(">", lt + 2);
      pos = end < 0 ? src.length : end + (isComment ? 3 : 1);
      continue;
    }
    if (next === "?") {
      const end = src.indexOf(">", lt + 2);
      pos = end < 0 ? src.length : end + 1;
      continue;
    }
    const scan = scanTag(src, lt);
    if (scan === "literal") {
      text("<");
      pos = lt + 1;
      continue;
    }
    if (scan === "unterminated") {
      // No tag end anywhere in the tail: browsers wouldn't emit it either, so
      // the "<" and everything after is literal text (and scanning stops,
      // which keeps adversarial input linear).
      text(src.slice(lt));
      pos = src.length;
      break;
    }
    pos = scan.end;
    const tag = scan.tag.toLowerCase();
    const closing = scan.closing;
    if (skip) {
      if (tag === skip.tag) skip.depth += closing ? -1 : 1;
      if (skip.depth === 0) skip = null;
      continue;
    }
    if (closing) {
      const i = VOID.has(tag) ? -1 : findOpen(tag);
      if (i >= 0) closeTo(i);
      continue;
    }
    if (profile.rawText.has(tag)) {
      // Skip straight to the end tag: exec from lastIndex scans forward
      // without copying the tail.
      const re = RAW_END_RE.get(tag) ?? new RegExp(`</${tag}[\\s/>]`, "gi");
      re.lastIndex = pos;
      const m = re.exec(src);
      pos = m ? m.index : src.length;
      continue;
    }
    if (profile.dropped.has(tag)) {
      if (!scan.raw.endsWith("/>")) skip = { tag, depth: 1 };
      continue;
    }
    const extra = profile.allowed.get(tag);
    if (!extra) continue;
    const { attrs, src: hasSrc } = cleanAttrs(scan.attrs, extra, tag, profile);
    // An image whose source didn't survive shows nothing.
    if (tag === "img" && !hasSrc) continue;
    if (CLOSES_P.has(tag)) closeNearest(["p"], ["table", "td", "th", "caption"]);
    if (tag === "li") closeNearest(["li"], ["ul", "ol", "table", "td", "th"]);
    else if (tag === "td" || tag === "th") closeNearest(["td", "th"], ["tr", "table"]);
    else if (tag === "tr") closeNearest(["tr"], ["thead", "tbody", "tfoot", "table"]);
    else if (tag === "thead" || tag === "tbody" || tag === "tfoot") {
      closeNearest(["thead", "tbody", "tfoot"], ["table"]);
    }
    // Over the depth cap the tag unwraps: its children keep flowing inside
    // the current context, the element itself never opens.
    if (!VOID.has(tag) && open.length >= MAX_OPEN) continue;
    parts.push(`<${tag}${attrs}>`);
    if (!VOID.has(tag)) {
      open.push(tag);
      let list = slots.get(tag);
      if (!list) slots.set(tag, (list = []));
      list.push(open.length - 1);
    }
  }
  text(src.slice(pos));
  closeTo(0);
  return parts.join("");
}

/**
 * Signature HTML reduced to what is safe to render in the app and send:
 * tables and their layout attributes, inline styles, links (http, mailto, tel)
 * and images (http, cid, data:image) survive; scripts, `<style>` blocks,
 * forms, frames, SVG, comments, event handlers, classes and ids go. Source
 * formatting (line breaks, indentation) is kept, so the HTML editor shows the
 * user's own markup back. Idempotent.
 */
export function sanitizeSignatureHtml(html: string): string {
  return sanitizeWith(SIGNATURE_PROFILE, html);
}

/**
 * Composer-body HTML reduced to what is safe to keep in the live editor DOM
 * (and therefore in drafts and outgoing mail). Everything the composer itself
 * produces is a fixed point: the formatting tags, lists, blockquotes, tables
 * and presentational attributes email HTML uses, links (http, https, mailto,
 * tel, cid), inline images (http, cid, raster data:), mention chips
 * (`span.co-mention` + contenteditable + data-email) and the signature block's
 * `co-signature` class. Styles are filtered to a presentational property
 * allowlist; scripts, styles, frames, forms, SVG/MathML, comments, event
 * handlers, ids and other classes go. Idempotent.
 */
export function sanitizeEditorHtml(html: string): string {
  return sanitizeWith(EDITOR_PROFILE, html);
}
