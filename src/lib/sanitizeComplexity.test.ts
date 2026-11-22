import { describe, expect, it } from "vitest";
import {
  replaceSignature,
  sanitizeEditorHtml,
  sanitizeSignatureHtml,
  stripSignature,
} from "./signatures";
import { htmlToText, isHtmlEmpty, stripFormatting } from "./richtext";

/**
 * Scaling tests: not a list of known-bad inputs but a generator that
 * recombines every fragment the scanners treat specially, then asserts time
 * at 2n stays under ~3x time at n. A super-linear helper anywhere in the
 * pipeline (tokenizing, attrs, styles, url checks, tag mapping, whitespace
 * collapsing) blows that bound long before the absolute times look bad.
 */

const FRAGMENTS = [
  // token soup
  "<", ">", "</", "<!--", "-->", "<!", "<?", '"', "'", "=", " ", "\t",
  // entities and CSS function shapes
  "&", "&#", "&#x", ";", "url(", ")", "(", ":", "-", "\\", "/*", "*/",
  "expression(", "image-set(", "javascript:",
  // attribute openers
  'style="', "style='", 'class="', 'href="', 'title="', 'data-email="',
  'src="data:image/png;base64,',
  // tag names across every category: allowed, raw-text, dropped, void,
  // table parts, the classes the editor relies on
  "<br>", "<br ", "<div ", "<div>", "</div>", "<p>x<div>", "<span ", "<span>",
  '<span class="co-mention">', '<div class="co-signature">', "co-mention",
  "co-signature", "data-email", "onerror=",
  "script", "<script", "</script>", "<style", "</style>", "title", "textarea",
  "iframe", "svg", "math", "select", "template", "<img ", "<a ", "<pre",
  "</pre>", "<table", "<td", "<tr", "<li", "<blockquote>", "x", "a-", "aaaa",
];

const SANITIZERS = { editor: sanitizeEditorHtml, signature: sanitizeSignatureHtml };
const BODY_FNS: Record<string, (s: string) => unknown> = {
  stripSignature,
  replaceSignature: (s) => replaceSignature(s, "<p>sig</p>"),
  htmlToText,
  stripFormatting,
  isHtmlEmpty,
};

const repeatTo = (frag: string, size: number) => frag.repeat(Math.ceil(size / frag.length));
const alternate = (a: string, b: string, size: number) =>
  (a + b).repeat(Math.ceil(size / (a.length + b.length)));
const inAttr = (frag: string, attr: string, size: number) => {
  const inner = repeatTo(frag, size);
  return attr === "href"
    ? `<a href="${inner}">x</a>`
    : `<div ${attr}="${inner}">x</div>`;
};

const N = 100_000;
const N2 = 200_000;
// Floor so that sub-second linear cases can't flake on timer/GC noise. A
// real quadratic costs seconds at these sizes, so the bound keeps its bite.
const FLOOR_MS = 150;

const timeMin = (fn: (s: string) => unknown, input: string, reps = 1): number => {
  fn(input); // warm up JIT/allocs outside the measurement
  let best = Infinity;
  for (let r = 0; r < reps; r += 1) {
    const t0 = performance.now();
    fn(input);
    best = Math.min(best, performance.now() - t0);
  }
  return best;
};

/** t2 must stay under ~3x t1 (with a floor). One fast measurement first;
 *  retries with more reps only when the bound is at risk, so jitter can be
 *  retried away without paying for reps on every case. */
function measure(fn: (s: string) => unknown, small: string, large: string) {
  let t1 = timeMin(fn, small);
  let t2 = timeMin(fn, large);
  for (let r = 0; r < 3 && t2 > Math.max(t1 * 3, FLOOR_MS); r += 1) {
    t1 = timeMin(fn, small, 2);
    t2 = timeMin(fn, large, 2);
  }
  return { t1, t2 };
}

/** Output safety invariants: escaped text can hold "javascript:" or
 *  "onclick=" literally inside an attribute value, so only look at the parts
 *  of each emitted tag outside its quoted values. */
function leaked(out: string): boolean {
  for (let lt = out.indexOf("<"); lt >= 0; lt = out.indexOf("<", lt + 1)) {
    const gt = out.indexOf(">", lt);
    if (gt < 0) return false;
    const tag = out.slice(lt, gt + 1).toLowerCase();
    if (/^<\/?script\b/.test(tag)) return true;
    const names = tag.replace(/="[^"]*"/g, "");
    if (/\son[a-z][a-z0-9-]*\s*=?/.test(names)) return true;
    if (/(?:href|src|background)="[^"]*javascript:/.test(tag)) return true;
  }
  return false;
}

function checkInvariants(input: string) {
  for (const fn of Object.values(SANITIZERS)) {
    const once = fn(input);
    expect(fn(once), "idempotent").toBe(once);
    expect(leaked(once), "sanitized").toBe(false);
  }
}

function checkScaling(
  name: string,
  make: (size: number) => string,
  fns: Record<string, (s: string) => unknown> = { ...SANITIZERS, ...BODY_FNS },
) {
  const small = make(N);
  const large = make(N2);
  checkInvariants(small);
  for (const [fname, fn] of Object.entries(fns)) {
    const { t1, t2 } = measure(fn, small, large);
    expect(t2, `${name} / ${fname}`).toBeLessThan(Math.max(t1 * 3, FLOOR_MS));
  }
}

const checkSanitizerScaling = (name: string, make: (size: number) => string) =>
  checkScaling(name, make, SANITIZERS);

describe("sanitizer and body-scan complexity", () => {
  it(
    "stays linear when one fragment repeats",
    () => {
      for (const frag of FRAGMENTS) {
        checkScaling(`"${frag.slice(0, 24)}" x n`, (size) => repeatTo(frag, size));
      }
    },
    60_000,
  );

  it(
    "stays linear on fragment runs inside attribute values",
    () => {
      for (const attr of ["style", "href", "title", "class"]) {
        for (const frag of FRAGMENTS) {
          checkSanitizerScaling(`${attr}="${frag.slice(0, 18)}" x n`, (size) =>
            inAttr(frag, attr, size),
          );
        }
      }
    },
    60_000,
  );

  it(
    "stays linear on alternating fragment pairs",
    () => {
      const pairs: [string, string][] = [
        ["<p>", "<div>"],
        ["<span ", '" '],
        ["<a href=", '">'],
        ["<span class=\"co-mention\">", "</span>"],
        ["<script", "</script>"],
        ["<!--", "-->"],
        ["url(", ")"],
        ["<td", "<tr"],
        ["&", ";"],
        ["<br>", "x"],
        ["<div ", 'class="'],
        ["<pre", "</pre>"],
      ];
      for (const [a, b] of pairs) {
        checkScaling(`"${a.slice(0, 14)}"/"${b.slice(0, 14)}" alternating`, (size) =>
          alternate(a, b, size),
        );
      }
      // Every fragment interleaved with text, sanitizers only: the body
      // functions get their alternation coverage from the pairs above, and
      // this keeps the sweep inside the few-seconds budget.
      for (const frag of FRAGMENTS) {
        checkSanitizerScaling(`"${frag.slice(0, 18)}"/"x" alternating`, (size) =>
          alternate(frag, "x", size),
        );
      }
    },
    60_000,
  );
});
