import { describe, expect, it } from "vitest";
import { sanitizeEditorHtml, sanitizeSignatureHtml } from "./signatures";
import { draftBodyForSave } from "./draftBody";

/** Legitimate content must survive sanitizing intact: a URL (or data URI) is
 *  kept whole or dropped whole, never cut - a truncated URL is a different
 *  URL and a truncated base64 image is a corrupt file that would be saved
 *  and sent. */

const pngData = (size: number) => `data:image/png;base64,${"A".repeat(size)}`;

describe("content preservation", () => {
  it("keeps inline image data URIs byte-for-byte through both profiles and the save path", () => {
    for (const size of [200_000, 5_000_000]) {
      const src = pngData(size);
      const html = `<div>before<img src="${src}" alt="logo">after</div>`;
      expect(sanitizeEditorHtml(html)).toBe(html);
      expect(sanitizeSignatureHtml(html)).toBe(html);
      expect(draftBodyForSave(html, "", false).bodyHtml).toContain(`src="${src}"`);
    }
  });

  it("keeps or drops a long href whole, never alters it", () => {
    for (const len of [6_000, 40_000]) {
      const href = `https://example.com/${"a".repeat(len)}`;
      const html = `<a href="${href}">link</a>`;
      for (const fn of [sanitizeEditorHtml, sanitizeSignatureHtml]) {
        const out = fn(html);
        if (out.includes("href=")) {
          // Present: it must be the complete URL.
          expect(out).toBe(`<a href="${href}">link</a>`);
        } else {
          // Dropped: nothing of the URL may remain.
          expect(out).not.toContain(href.slice(0, 64));
        }
      }
    }
    // A 6 KB href is well under the caps and must survive whole.
    const href = `https://example.com/${"a".repeat(6_000)}`;
    expect(sanitizeEditorHtml(`<a href="${href}">x</a>`)).toBe(`<a href="${href}">x</a>`);
    expect(sanitizeSignatureHtml(`<a href="${href}">x</a>`)).toBe(`<a href="${href}">x</a>`);
  });

  it("truncates long text attributes at a code-point boundary without cutting an entity", () => {
    const title = `${"t".repeat(3_000)}&amp;${"u".repeat(3_000)}`;
    const once = sanitizeEditorHtml(`<div title="${title}">x</div>`);
    const value = /title="([^"]*)"/.exec(once)![1];
    expect(value.length).toBeLessThanOrEqual(4 * 1024);
    expect(value).not.toMatch(/&[#a-zA-Z0-9]*$/); // no half-written reference
    expect(sanitizeEditorHtml(once)).toBe(once); // truncation is a fixed point
    // A surrogate pair straddling the cap is dropped whole, never split.
    const emoji = `${"t".repeat(4_095)}\u{1f600}zzz`;
    const cut = sanitizeEditorHtml(`<div title="${emoji}">x</div>`);
    expect(cut).not.toContain("\u{1f600}");
    expect(cut).not.toMatch(/[\ud800-\udfff]/);
  });

  it("keeps long realistic signatures unchanged", () => {
    const logo = `<img src="${pngData(150_000)}">`;
    const style = `font-family:Arial;${"color:#123456;".repeat(600)}`;
    const html = `<table><tr><td style="${style}"><b>Name</b><br>${logo}<a href="https://example.com/${"q".repeat(2_000)}">site</a></td></tr></table>`;
    expect(sanitizeSignatureHtml(html)).toBe(html);
  });

  it("treats realistic Outlook/Gmail/Apple fragments as fixed points with no lost text", () => {
    const textOf = (h: string) =>
      h
        .replace(/<!--[\s\S]*?-->/g, "")
        .replace(/<script\b[\s\S]*?<\/script>/gi, "")
        .replace(/<style\b[\s\S]*?<\/style>/gi, "")
        .replace(/<[^>]+>/g, "")
        .replace(/\s+/g, " ")
        .trim();
    const fragments = [
      // Outlook desktop: mso styles, <o:p>, conditional comment scaffolding.
      `<p class="MsoNormal"><span style="font-family:'Calibri',sans-serif;mso-fareast-font-family:'Times New Roman'">Quarterly numbers<o:p></o:p></span></p>` +
        `<!--[if mso]><table><tr><td><![endif]--><table><tr><td style="padding:6pt">cell one</td><td>cell two</td></tr></table><!--[if mso]></td></tr></table><![endif]-->`,
      // Gmail reply: gmail_quote classes, dir, single-quoted attrs.
      `<div dir="ltr">new reply text</div><div class="gmail_extra"><div class="gmail_quote">On Mon wrote:<blockquote class="gmail_quote" style="margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex"><div dir="ltr">quoted body text</div></blockquote></div></div>`,
      // Apple Mail: html/body wrappers, font tags, nbsp chains, <br> endings.
      `<html><body style="word-wrap:break-word;-webkit-nbsp-mode:space;line-break:after-white-space"><div>apple body&nbsp;&nbsp;</div><div><font face="Helvetica" size="3">signature text</font></div><br></body></html>`,
      // Deeply nested table layout signature with long inline styles.
      `<table cellpadding="0" cellspacing="0"><tr><td><table><tr><td style="font-size:12px;line-height:1.4;${"margin:0;".repeat(50)}"><b>N&nbsp;Doe</b><br><span style="color:#666666">Engineer</span></td></tr></table></td></tr></table>`,
    ];
    for (const html of fragments) {
      const once = sanitizeEditorHtml(html);
      expect(sanitizeEditorHtml(once)).toBe(once); // fixed point
      expect(textOf(once)).toBe(textOf(html)); // no text lost
    }
  });
});
