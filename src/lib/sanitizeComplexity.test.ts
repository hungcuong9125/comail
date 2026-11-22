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
const FLOOR_MS = 300;
const REPS = 7;

const timeOnce = (fn: (s: string) => unknown, input: string): number => {
  const t0 = performance.now();
  fn(input);
  return performance.now() - t0;
};

/** Min of `reps` timed runs per side, collected interleaved so both see the
 *  same load distribution. The minimum is the least noise-sensitive
 *  estimator of true cost: a preemption inflates a sample, rarely all
 *  `reps` of them, so on a loaded machine both mins still land near the
 *  true costs and their ratio stays ~2 for a linear scan. */
function measure(fn: (s: string) => unknown, small: string, large: string) {
  fn(small);
  fn(large);
  let t1 = Infinity;
  let t2 = Infinity;
  for (let r = 0; r < REPS; r += 1) {
    t1 = Math.min(t1, timeOnce(fn, small));
    t2 = Math.min(t2, timeOnce(fn, large));
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

/** A seeded PRNG so failures reproduce. */
function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

/** Builds input only from constructs the editor allowlist keeps: allowed
 *  tags, allowed attributes with safe values, safe URLs. The oracle below
 *  asserts every src/href value survives unchanged - preservation is what
 *  the timing-only tests can't see. */
function cleanDocument(seed: number, size: number): string {
  const rand = rng(seed);
  const pick = <T>(xs: readonly T[]) => xs[Math.floor(rand() * xs.length)];
  const TAGS = [
    "div", "p", "span", "b", "strong", "i", "em", "u", "br", "ul", "ol", "li",
    "blockquote", "table", "tr", "td", "th", "thead", "tbody", "h2", "pre", "a", "img",
  ] as const;
  const ATTRS = [
    () => `align="${pick(["left", "right", "center"])}"`,
    () => `width="${1 + Math.floor(rand() * 800)}"`,
    () => `title="${pick(["tip", "info here", "a&amp;b"])}"`,
    () => `style="${pick([
      "color:#123456",
      "font-weight:bold;margin:0px",
      "text-align:center;line-height:1.4",
      "border-left:1px solid rgb(204,204,204)",
    ])}"`,
  ] as const;
  const hrefs = [
    `https://example.com/${"p".repeat(10 + Math.floor(rand() * 4_000))}`,
    `mailto:a${Math.floor(rand() * 999)}@b.co`,
    "tel:+15551234",
    "cid:part1.xyz@mail",
  ];
  const srcs = [
    `https://cdn.example.com/i${Math.floor(rand() * 99)}.png`,
    `data:image/png;base64,${"B".repeat(2_000 + Math.floor(rand() * 30_000))}`,
    `data:image/jpeg;base64,${"C".repeat(5_000)}`,
  ];
  const out: string[] = [];
  let len = 0;
  while (len < size) {
    const tag = pick(TAGS);
    let piece: string;
    if (tag === "a") {
      piece = `<a href="${pick(hrefs)}">link text</a>`;
    } else if (tag === "img") {
      piece = `<img src="${pick(srcs)}" alt="pic">`;
    } else if (tag === "br") {
      piece = "<br>";
    } else if (tag === "span" && rand() < 0.3) {
      piece = `<span class="co-mention" contenteditable="false" data-email="x${Math.floor(rand() * 99)}@y.co">@x</span>`;
    } else if (tag === "div" && rand() < 0.1) {
      piece = `<div class="co-signature">sig</div>`;
    } else {
      const attrs = rand() < 0.5 ? ` ${pick(ATTRS)()}` : "";
      piece = rand() < 0.5 ? `<${tag}${attrs}>text ${Math.floor(rand() * 9)}</${tag}>` : `<${tag}${attrs}>`;
    }
    out.push(piece);
    len += piece.length;
  }
  return out.join("");
}

describe("sanitizer and body-scan complexity", () => {
  it(
    "stays linear when one fragment repeats",
    () => {
      for (const frag of FRAGMENTS) {
        checkScaling(`"${frag.slice(0, 24)}" x n`, (size) => repeatTo(frag, size));
      }
    },
    180_000,
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
    180_000,
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
    180_000,
  );

  it("preserves every allowed src/href byte-for-byte", () => {
    for (let seed = 1; seed <= 30; seed += 1) {
      const input = cleanDocument(seed, 30_000);
      const urls = [...input.matchAll(/(?:src|href)="([^"]*)"/g)].map((m) => m[1]);
      expect(urls.length).toBeGreaterThan(0);
      // Editor profile keeps everything the generator emits.
      const editorOut = sanitizeEditorHtml(input);
      for (const u of urls) expect(editorOut, `editor lost ${u.slice(0, 48)}`).toContain(u);
      expect(sanitizeEditorHtml(editorOut)).toBe(editorOut);
      // Signature profile: cid: links are outside its link allowlist.
      const sigOut = sanitizeSignatureHtml(input);
      for (const u of urls.filter((u) => !u.startsWith("cid:"))) {
        expect(sigOut, `sig lost ${u.slice(0, 48)}`).toContain(u);
      }
      expect(sanitizeSignatureHtml(sigOut)).toBe(sigOut);
    }
  });
});
