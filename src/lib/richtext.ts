/** Conversions between the composer's rich HTML body and the plain-text
 *  fallback that goes out as text/plain (and powers snippets/search). The
 *  converter only needs to be faithful for the markup our own editor emits
 *  (div/p/br, b/i/u/s, blockquote, ul/ol/li, a, img) but stays tolerant of
 *  anything pasted in. */

const ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
  "&apos;": "'",
  "&nbsp;": " ",
};

/** One match per reference, so nothing is decoded twice (`&amp;lt;` stays
 *  "&lt;", the text the author typed). Numeric references that don't name a
 *  scalar value (above U+10FFFF, surrogates, junk) keep their literal text
 *  instead of throwing in fromCodePoint. */
const ENTITY_RE = /&(amp|lt|gt|quot|apos|nbsp);|&#(\d+);|&#x([0-9a-f]+);/gi;

export function decodeEntities(s: string): string {
  return s.replace(ENTITY_RE, (m, named: string | undefined, dec: string | undefined, hex: string | undefined) => {
    if (named !== undefined) return ENTITIES[`&${named.toLowerCase()};`] ?? m;
    const cp = dec !== undefined ? Number(dec) : parseInt(hex ?? "", 16);
    if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return m;
    return String.fromCodePoint(cp);
  });
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** Plain text -> minimal HTML (escaped, newlines as <br>). */
export function textToHtml(text: string): string {
  if (!text) return "";
  return escapeHtml(text).replace(/\n/g, "<br>");
}

// --- Linear tag scans ------------------------------------------------------
// Everything below walks the source once: `<` positions come from indexOf
// over disjoint regions and a tag ends at the next `>`. The `[^>]*` and lazy
// `[\s\S]*?` regexes these replace re-scanned the tail per unmatched opener -
// quadratic on `<div ` or `<!--` repeated with no closer.

const WS = " \t\f\r\n";

/** A `<name` or `</name` (with a `\b`-like boundary) at `pos`: the index after
 *  its `>`, 0 when `pos` doesn't start one of `names`, -1 when it does but no
 *  `>` exists anywhere after - nothing further down can match either. */
function tagAt(lower: string, pos: number, names: ReadonlySet<string>): number {
  if (lower[pos] !== "<") return 0;
  let i = pos + 1;
  if (lower[i] === "/") i += 1;
  const start = i;
  while (i < lower.length && /[a-z0-9]/.test(lower[i])) i += 1;
  if (!names.has(lower.slice(start, i))) return 0;
  const boundary = lower[i];
  if (boundary !== undefined && /[a-z0-9_]/.test(boundary)) return 0;
  const gt = lower.indexOf(">", i);
  return gt < 0 ? -1 : gt + 1;
}

/** Index of `</name>` exactly (the close the `[\s\S]*?<\/name>` patterns
 *  found - `</a attr>` didn't count), or -1, memoized per tag name over one
 *  fixed `lower`: an absent close is
 *  remembered, so n unmatched openers don't each rescan the tail; a found
 *  position is reused while it is still ahead of the query point. */
function makeCloseFinder(lower: string): (pos: number, name: string) => number {
  const cache = new Map<string, number>();
  return (pos, name) => {
    const cached = cache.get(name);
    if (cached === -1) return -1;
    if (cached !== undefined && cached >= pos) return cached;
    let p = pos;
    for (;;) {
      const c = lower.indexOf(`</${name}`, p);
      if (c < 0) {
        cache.set(name, -1);
        return -1;
      }
      if (lower[c + name.length + 2] === ">") {
        cache.set(name, c);
        return c;
      }
      p = c + 1;
    }
  };
}

/** Attribute `name`'s value inside a raw tag string, or null. `form` keeps the
 *  shapes the regexes had: "double" only accepts `name="…"`, "any" also
 *  single quotes and a bare value. */
function getAttr(tag: string, name: string, form: "double" | "any"): string | null {
  const lower = tag.toLowerCase();
  let pos = 0;
  for (;;) {
    const at = lower.indexOf(name, pos);
    if (at < 0) return null;
    const before = lower[at - 1];
    if (before !== undefined && /[a-z0-9_]/.test(before)) {
      pos = at + 1;
      continue;
    }
    let i = at + name.length;
    while (i < tag.length && /\s/.test(tag[i])) i += 1;
    if (tag[i] !== "=") {
      pos = at + 1;
      continue;
    }
    i += 1;
    while (i < tag.length && /\s/.test(tag[i])) i += 1;
    const q = tag[i];
    if (q === '"') {
      const close = tag.indexOf('"', i + 1);
      return close < 0 ? null : tag.slice(i + 1, close);
    }
    if (form === "any" && q === "'") {
      const close = tag.indexOf("'", i + 1);
      return close < 0 ? null : tag.slice(i + 1, close);
    }
    if (form === "any") {
      const start = i;
      while (i < tag.length && !/[\s>]/.test(tag[i])) i += 1;
      if (i > start) return tag.slice(start, i);
    }
    return null;
  }
}

interface TagHit {
  name: string;
  end: boolean;
  lt: number;
  gt: number;
}

/** Each `<name …>`/`</name>` token through `cb`: it returns the replacement
 *  and where its match ends (it may swallow a `</name>`), or null to leave
 *  the token in the text. Same token shape as the old `<name\b[^>]*>`
 *  regexes, but the `>` is found by indexOf once. */
function mapTags(
  s: string,
  cb: (
    t: TagHit,
    lower: string,
    close: (pos: number, name: string) => number,
  ) => { out: string; end: number } | null,
): string {
  const lower = s.toLowerCase();
  const close = makeCloseFinder(lower);
  const out: string[] = [];
  let pos = 0;
  while (pos < s.length) {
    const lt = lower.indexOf("<", pos);
    if (lt < 0) {
      out.push(s.slice(pos));
      break;
    }
    const end = lower[lt + 1] === "/";
    let i = lt + (end ? 2 : 1);
    const nameStart = i;
    while (i < lower.length && /[a-z0-9]/.test(lower[i])) i += 1;
    const name = lower.slice(nameStart, i);
    const boundary = lower[i];
    if (name.length === 0 || (boundary !== undefined && /[a-z0-9_]/.test(boundary))) {
      out.push(s.slice(pos, lt + 1));
      pos = lt + 1;
      continue;
    }
    const gt = lower.indexOf(">", i);
    if (gt < 0) {
      out.push(s.slice(pos));
      break;
    }
    const rep = cb({ name, end, lt, gt }, lower, close);
    if (!rep) {
      out.push(s.slice(pos, gt + 1));
      pos = gt + 1;
      continue;
    }
    out.push(s.slice(pos, lt), rep.out);
    pos = rep.end;
  }
  return out.join("");
}

/** `<` + non-`>` run + `>` removed - the `/<[^>]+>/g` pass, linear. */
function stripTags(s: string): string {
  const out: string[] = [];
  let pos = 0;
  for (;;) {
    const lt = s.indexOf("<", pos);
    if (lt < 0) {
      out.push(s.slice(pos));
      break;
    }
    const gt = s.indexOf(">", lt + 1);
    if (gt < 0) {
      out.push(s.slice(pos));
      break;
    }
    if (gt === lt + 1) {
      // `<>` isn't a match for `<[^>]+>`: emit the `<` and keep scanning.
      out.push(s.slice(pos, lt + 1));
      pos = lt + 1;
      continue;
    }
    out.push(s.slice(pos, lt));
    pos = gt + 1;
  }
  return out.join("");
}

/** Comments and <style>/<script> elements (content included) removed. One
 *  pass; an opener whose close never comes is left as literal text, which is
 *  what the non-matching lazy regex did with it too. */
function stripDangerous(html: string): string {
  const lower = html.toLowerCase();
  const closeTag = makeCloseFinder(lower);
  const out: string[] = [];
  let pos = 0;
  // Once a `-->` search fails there are none left anywhere - remember that
  // instead of rescanning the tail per `<!--`.
  let noCommentEnd = false;
  while (pos < html.length) {
    const lt = lower.indexOf("<", pos);
    if (lt < 0) {
      out.push(html.slice(pos));
      break;
    }
    if (lower.startsWith("<!--", lt)) {
      const end = noCommentEnd ? -1 : lower.indexOf("-->", lt + 4);
      if (end < 0) {
        noCommentEnd = true;
        out.push(html.slice(pos, lt + 4));
        pos = lt + 4;
      } else {
        out.push(html.slice(pos, lt));
        pos = end + 3;
      }
      continue;
    }
    const rawName =
      lower.startsWith("script", lt + 1) ? "script" :
      lower.startsWith("style", lt + 1) ? "style" : null;
    // Same `\b` the old regexes had: <scriptx> is an ordinary unknown tag.
    const raw =
      rawName && /[^a-z0-9_]/.test(lower[lt + 1 + rawName.length] ?? " ")
        ? rawName
        : null;
    if (raw) {
      const gt = lower.indexOf(">", lt + 1);
      if (gt < 0) {
        out.push(html.slice(pos));
        break;
      }
      const close = closeTag(gt + 1, raw);
      if (close < 0) {
        // No `</name>` anywhere: the tag is literal text, as before.
        out.push(html.slice(pos, gt + 1));
        pos = gt + 1;
        continue;
      }
      out.push(html.slice(pos, lt));
      pos = close + raw.length + 3;
      continue;
    }
    out.push(html.slice(pos, lt + 1));
    pos = lt + 1;
  }
  return out.join("");
}

/** Tags that break the line, whose adjacent literal spaces render as
 *  nothing. */
const LINE_TAGS = new Set(
  "br div p h1 h2 h3 h4 h5 h6 ul ol li table thead tbody tfoot tr td th blockquote".split(" "),
);

/** One non-<pre> stretch: a whitespace run spanning a line break collapses to
 *  " ", and literal spaces beside a line-breaking tag vanish. The regex pair
 *  this replaces backtracked over every position of a long space or `<` run. */
function collapseSegment(seg: string): string {
  const lower = seg.toLowerCase();
  const out: string[] = [];
  let pending = "";
  let pos = 0;
  let textStart = 0;
  const flushText = (upto: number) => {
    if (upto > textStart) out.push(seg.slice(textStart, upto));
    textStart = upto;
  };
  // Whitespace buffered between tokens: emitted whole, or without its
  // trailing " "s when a line-breaking tag follows (` *` before the tag).
  const emitPending = (trimmed: boolean) => {
    let k = pending.length;
    if (trimmed) while (k > 0 && pending[k - 1] === " ") k -= 1;
    if (k) out.push(pending.slice(0, k));
    pending = "";
  };
  const wsRun = (at: number): { end: number; nl: boolean } => {
    let i = at;
    let nl = false;
    while (i < seg.length && WS.includes(seg[i])) {
      if (seg[i] === "\r" || seg[i] === "\n") nl = true;
      i += 1;
    }
    return { end: i, nl };
  };
  while (pos < seg.length) {
    const c = seg[pos];
    if (WS.includes(c)) {
      const run = wsRun(pos);
      flushText(pos);
      pending += run.nl ? " " : seg.slice(pos, run.end);
      pos = run.end;
      textStart = pos;
      continue;
    }
    if (c === "<") {
      const end = tagAt(lower, pos, LINE_TAGS);
      if (end < 0) {
        emitPending(false);
        flushText(seg.length);
        break;
      }
      if (end > 0) {
        flushText(pos);
        emitPending(true);
        out.push(seg.slice(pos, end));
        pos = end;
        // ` *` after the tag, evaluated on the collapsed form: a ws-run
        // holding a line break became " " and so goes entirely; a literal
        // run loses only its leading spaces.
        const run = wsRun(pos);
        pos = run.nl ? run.end : pos;
        while (pos < seg.length && seg[pos] === " ") pos += 1;
        textStart = pos;
        continue;
      }
    }
    // Plain text char: it follows any buffered whitespace, which must be
    // emitted before the text slice it belongs to.
    emitPending(false);
    pos += 1;
  }
  emitPending(false);
  flushText(seg.length);
  return out.join("");
}

/** Drop the whitespace that only formats the markup (an HTML signature arrives
 *  indented): a run spanning a line break renders as one space, and a space
 *  beside a line-breaking tag as nothing. <pre> blocks keep theirs. The
 *  `<pre>` spans are found with indexOf rather than the lazy `[\s\S]*?` split
 *  that quadratically retried from every unmatched `<pre`. */
function collapseSourceWhitespace(html: string): string {
  const lower = html.toLowerCase();
  const out: string[] = [];
  let pos = 0;
  for (;;) {
    const lt = lower.indexOf("<pre", pos);
    if (lt < 0) {
      out.push(collapseSegment(html.slice(pos)));
      break;
    }
    const boundary = lower[lt + 4];
    if (boundary !== undefined && /[a-z0-9_]/.test(boundary)) {
      // `<prefix` isn't a <pre> tag: emit through the `<` and keep looking.
      out.push(collapseSegment(html.slice(pos, lt + 1)));
      pos = lt + 1;
      continue;
    }
    const gt = lower.indexOf(">", lt + 4);
    if (gt < 0) {
      out.push(collapseSegment(html.slice(pos)));
      break;
    }
    let preEnd = -1;
    let p = gt + 1;
    for (;;) {
      const c = lower.indexOf("</pre", p);
      if (c < 0) break;
      if (lower[c + 5] === ">") {
        preEnd = c + 6;
        break;
      }
      p = c + 1;
    }
    if (preEnd < 0) {
      out.push(collapseSegment(html.slice(pos)));
      break;
    }
    out.push(collapseSegment(html.slice(pos, lt)), html.slice(lt, preEnd));
    pos = preEnd;
  }
  return out.join("");
}

/** Rich HTML -> plain text fallback. Block elements become newlines,
 *  blockquotes become "> " prefixes, list items become "- ", images become
 *  their alt text (or are dropped). */
export function htmlToText(html: string): string {
  if (!html) return "";
  let s = stripDangerous(html);
  s = collapseSourceWhitespace(s);

  // Links: keep the target when it isn't the same as the text.
  s = mapTags(s, (t, _lower, closeTag) => {
    if (t.end || t.name !== "a") return null;
    const href = getAttr(s.slice(t.lt, t.gt + 1), "href", "double");
    if (href == null) return null;
    const close = closeTag(t.gt + 1, "a");
    if (close < 0) return null;
    const text = stripTags(s.slice(t.gt + 1, close));
    return {
      out: text.trim() === href.trim() || !href ? text : `${text} (${href})`,
      end: close + "</a>".length,
    };
  });

  // Images: alt text or nothing.
  s = mapTags(s, (t) => {
    if (t.end || t.name !== "img") return null;
    const alt = getAttr(s.slice(t.lt, t.gt + 1), "alt", "double");
    return { out: alt ? `[${alt}]` : "", end: t.gt + 1 };
  });

  // Blockquote boundaries -> control markers handled linewise below. br -> \n,
  // cell closes -> \t, <li> -> "- ", other block tags -> one newline (a
  // closing </li>/</tr> contributes none - the next row break supplies it).
  const OPEN_NL = new Set("div p h1 h2 h3 h4 h5 h6 ul ol tr table".split(" "));
  const CLOSE_NL = new Set("div p h1 h2 h3 h4 h5 h6 ul ol table".split(" "));
  s = mapTags(s, (t) => {
    if (t.name === "blockquote") return { out: t.end ? "\x02\n" : "\n\x01", end: t.gt + 1 };
    if (t.name === "br" && !t.end) return { out: "\n", end: t.gt + 1 };
    if ((t.name === "td" || t.name === "th") && t.end) return { out: "\t", end: t.gt + 1 };
    if (t.name === "li" && !t.end) return { out: "\n- ", end: t.gt + 1 };
    if (!t.end && OPEN_NL.has(t.name)) return { out: "\n", end: t.gt + 1 };
    if (t.end && CLOSE_NL.has(t.name)) return { out: "\n", end: t.gt + 1 };
    return null;
  });
  s = stripTags(s);
  s = decodeEntities(s);
  // Pull close markers up to the previous line so nested closes don't leave
  // orphan quote-prefix lines. Buffered \n's drop before \x02 and flush before
  // anything else - `\n+(?=\x02)` did the same but retried the run per
  // position when no marker followed.
  {
    const merged: string[] = [];
    let start = 0;
    for (let i = s.indexOf("\x02"); i >= 0; i = s.indexOf("\x02", i + 1)) {
      let j = i;
      while (j > start && s[j - 1] === "\n") j -= 1;
      merged.push(s.slice(start, j), "\x02");
      start = i + 1;
    }
    merged.push(s.slice(start));
    s = merged.join("");
  }

  // Apply "> " prefixes from the blockquote depth markers.
  // Markers always sit at line boundaries (opens at the start, closes at the
  // end), so opens take effect for their own line, closes after it.
  const out: string[] = [];
  let depth = 0;
  // Quote depth is capped for the same reason the sanitizer caps open
  // elements: without it, n unclosed <blockquote>s would emit O(n^2) of
  // "> " prefix. Real mail never nests quotes anywhere near this deep.
  const MAX_QUOTE_DEPTH = 256;
  for (const rawLine of s.split("\n")) {
    let line = rawLine;
    let opens = 0;
    let closes = 0;
    line = line.replace(/\x01/g, () => ((opens += 1), ""));
    line = line.replace(/\x02/g, () => ((closes += 1), ""));
    depth = Math.min(depth + opens, MAX_QUOTE_DEPTH);
    const prefix = "> ".repeat(depth);
    const joined = line.trim() === "" ? prefix.trimEnd() : prefix + line;
    let k = joined.length;
    while (k > 0 && (joined[k - 1] === " " || joined[k - 1] === "\t")) k -= 1;
    out.push(joined.slice(0, k));
    depth = Math.max(0, depth - closes);
  }

  return out
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

// Line-break / cell markers used while flattening. Neither is whitespace, so a
// blanket whitespace collapse can run without eating the structure.
const BR_MARK = "\x01";
const CELL_MARK = "\x02";

const RUN_BLOCK_TAGS = new Set(
  (
    "div p h1 h2 h3 h4 h5 h6 ul ol li tr table thead tbody tfoot blockquote pre " +
    "section article aside header footer address dl dt dd hr figure figcaption form fieldset"
  ).split(" "),
);

/** A maximal run of whitespace and block-boundary tags containing at least
 *  one tag collapses to a single line break - `(ws* tag ws*)+` tiled by hand
 *  so a space run or `<tag` run can't trigger the regex's quadratic retry. */
function collapseBlockRuns(s: string, marker: string): string {
  const lower = s.toLowerCase();
  const out: string[] = [];
  let pos = 0;
  while (pos < s.length) {
    let i = pos;
    while (i < s.length && /\s/.test(s[i])) i += 1;
    let end = tagAt(lower, i, RUN_BLOCK_TAGS);
    if (end <= 0) {
      if (end < 0) {
        out.push(s.slice(pos));
        break;
      }
      out.push(s.slice(pos, i + 1));
      pos = i + 1;
      continue;
    }
    // Run started: keep tiling ws*/tag while more block tags follow. The
    // trailing `\s*` of the last repetition belongs to the run either way.
    let j = end;
    for (;;) {
      let k = j;
      while (k < s.length && /\s/.test(s[k])) k += 1;
      end = tagAt(lower, k, RUN_BLOCK_TAGS);
      if (end <= 0) {
        j = k;
        break;
      }
      j = end;
    }
    // The ws before the first tag is inside the run's match, so only the
    // marker is emitted for the whole tiled span.
    out.push(marker);
    pos = j;
  }
  return out.join("");
}

/** Rebuild an <img> tag with only the attributes that carry content, dropping
 *  inline sizing/styling. */
function plainImg(tag: string): string {
  const src = getAttr(tag, "src", "double") ?? "";
  const alt = getAttr(tag, "alt", "double") ?? "";
  if (!src) return "";
  const altAttr = alt ? ` alt="${escapeHtml(decodeEntities(alt))}"` : "";
  return `<img src="${escapeHtml(decodeEntities(src))}"${altAttr}>`;
}

/** Rebuild a mention chip from the matched <span>...</span>, keeping only the
 *  attributes the chip needs - anything else on the source tag is dropped, so
 *  a forged chip can't smuggle handlers or styles through "plain text" mode. */
function plainMention(markup: string): string {
  const openEnd = markup.indexOf(">") + 1;
  const open = markup.slice(0, openEnd);
  const raw = getAttr(open, "data-email", "any") ?? "";
  const inner = markup.slice(openEnd, markup.length - "</span>".length);
  const text = stripTags(inner);
  return (
    `<span class="co-mention" contenteditable="false"` +
    ` data-email="${escapeHtml(decodeEntities(raw))}">` +
    `${escapeHtml(decodeEntities(text))}</span>`
  );
}

/**
 * Strip every formatting construct from `html`, keeping the text and its line
 * structure. Tables, lists, quotes, headings, fonts, colors and inline styles
 * all collapse to plain lines separated by <br>; table cells stay tab-separated
 * on their row's line.
 *
 * Images, "@" mention chips and links survive: they are content, not
 * formatting (a link keeps its href and its text, losing any markup inside).
 */
export function stripFormatting(html: string): string {
  if (!html) return "";

  // Content we hand back untouched, parked behind \x00<n>\x00 placeholders so
  // the tag-stripping pass below can't see it.
  const kept: string[] = [];
  const keep = (s: string) => `\x00${kept.push(s) - 1}\x00`;

  let s = stripDangerous(html);

  s = mapTags(s, (t) => {
    if (t.end || t.name !== "img") return null;
    return { out: keep(plainImg(s.slice(t.lt, t.gt + 1))), end: t.gt + 1 };
  });
  s = mapTags(s, (t, _lower, closeTag) => {
    if (t.end || t.name !== "span") return null;
    const tag = s.slice(t.lt, t.gt + 1);
    if (!getAttr(tag, "class", "any")?.includes("co-mention")) return null;
    const close = closeTag(t.gt + 1, "span");
    if (close < 0) return null;
    return { out: keep(plainMention(s.slice(t.lt, close + 7))), end: close + 7 };
  });
  s = mapTags(s, (t, _lower, closeTag) => {
    if (t.end || t.name !== "a") return null;
    const close = closeTag(t.gt + 1, "a");
    if (close < 0) return null;
    const href = getAttr(s.slice(t.lt, t.gt + 1), "href", "double") ?? "";
    // Inner markup goes, inner text (and any kept placeholder) stays.
    const text = stripTags(s.slice(t.gt + 1, close));
    const end = close + "</a>".length;
    if (!href || !text.trim()) return { out: text, end };
    return {
      out: keep(
        `<a href="${escapeHtml(decodeEntities(href))}">${escapeHtml(decodeEntities(text)).trim()}</a>`,
      ),
      end,
    };
  });

  s = mapTags(s, (t) => {
    if (!t.end && t.name === "br") return { out: BR_MARK, end: t.gt + 1 };
    if (t.end && (t.name === "td" || t.name === "th")) return { out: CELL_MARK, end: t.gt + 1 };
    return null;
  });
  // A whole run of adjacent block boundaries ("</li><li>", "</div><div>") is
  // one line break, not one per tag - only an explicit empty block leaves a
  // blank line, because its <br> already became a marker above.
  s = collapseBlockRuns(s, BR_MARK);
  s = stripTags(s);
  s = decodeEntities(s);
  // Source line breaks and indentation are formatting too.
  s = s.replace(/\s+/g, " ");

  const text = s
    .split(BR_MARK)
    .map((line) => line.split(CELL_MARK).join("\t").trim())
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  let out = escapeHtml(text).replace(/\n/g, "<br>");
  // Kept links can themselves hold an image/mention placeholder, so restore
  // until nothing is left parked.
  for (let pass = 0; pass < 3 && out.includes("\x00"); pass += 1) {
    out = out.replace(/\x00(\d+)\x00/g, (_, n: string) => kept[Number(n)] ?? "");
  }
  return out;
}

/** True when the HTML has no visible content (text or image). */
export function isHtmlEmpty(html: string): boolean {
  if (!html) return true;
  if (/<img\b/i.test(html)) return false;
  return htmlToText(html).trim() === "";
}
