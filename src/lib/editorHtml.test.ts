import { describe, expect, it } from "vitest";
import { sanitizeEditorHtml } from "./signatures";

/** Markup the composer itself produces: text blocks, inline formatting, a
 *  mention chip, a link, an inline image, a quote and the signature block. */
const EDITOR_BODY =
  "<div>Hello <b>world</b> <i>again</i> <u>u</u> <s>s</s></div>" +
  '<div><span class="co-mention" contenteditable="false" data-email="ann@acme.com">@Ann</span> hi</div>' +
  '<ul><li>one</li><li>two</li></ul><ol start="3"><li>three</li></ol>' +
  '<blockquote>quoted</blockquote>' +
  '<div><a href="https://acme.com" target="_blank">acme</a></div>' +
  '<div><img src="data:image/png;base64,iVBORw0KGgo="></div>' +
  '<div><img src="cid:logo@acme"></div>' +
  '<div class="co-signature"><div>Jane <b>Doe</b></div></div>' +
  "<div><br></div>";

describe("sanitizeEditorHtml", () => {
  it("keeps composer-produced markup as a fixed point", () => {
    expect(sanitizeEditorHtml(EDITOR_BODY)).toBe(EDITOR_BODY);
  });

  it("keeps the mention chip's attributes but only its own", () => {
    const hostile =
      '<span class="co-mention other" contenteditable="false" data-email="a@b.c" ' +
      'id="x" onclick="alert(1)" style="color:red"><b>@Ann</b></span>';
    // class is filtered to the chip token and handlers/ids go; a safe style
    // stays (style is a global allowed attribute, filtered by property).
    expect(sanitizeEditorHtml(hostile)).toBe(
      '<span class="co-mention" contenteditable="false" data-email="a@b.c" style="color:red"><b>@Ann</b></span>',
    );
    // contenteditable only survives as "false", and only on the chip path.
    expect(
      sanitizeEditorHtml('<span class="co-mention" contenteditable="true">x</span>'),
    ).toBe('<span class="co-mention">x</span>');
    // data-email stays span-only.
    expect(sanitizeEditorHtml('<div data-email="a@b.c">x</div>')).toBe("<div>x</div>");
  });

  it("keeps the signature class on divs, drops classes everywhere else", () => {
    expect(sanitizeEditorHtml('<div class="co-signature">x</div>')).toBe(
      '<div class="co-signature">x</div>',
    );
    expect(sanitizeEditorHtml('<div class="other co-signature">x</div>')).toBe(
      '<div class="co-signature">x</div>',
    );
    expect(sanitizeEditorHtml('<p class="co-signature">x</p>')).toBe("<p>x</p>");
    expect(sanitizeEditorHtml('<div class="gmail_quote">x</div>')).toBe("<div>x</div>");
  });

  it("keeps presentational inline styles, drops dangerous ones", () => {
    expect(
      sanitizeEditorHtml('<span style="color:#123;font-size:14px;text-align:center">x</span>'),
    ).toBe('<span style="color:#123;font-size:14px;text-align:center">x</span>');
    expect(
      sanitizeEditorHtml('<div style="color:red;position:fixed;top:0">x</div>'),
    ).toBe('<div style="color:red">x</div>');
    expect(sanitizeEditorHtml('<div style="background:url(javascript:alert(1))">x</div>')).toBe(
      "<div>x</div>",
    );
    expect(sanitizeEditorHtml('<div style="width:expression(alert(1))">x</div>')).toBe("<div>x</div>");
    // Generated content and layout hijacking are off the allowlist too.
    expect(
      sanitizeEditorHtml('<div style="z-index:99;transform:scale(2);content:&quot;x&quot;">x</div>'),
    ).toBe("<div>x</div>");
    const dataBg = '<td style="background:url(data:image/png;base64,AAAA) no-repeat">a</td>';
    expect(sanitizeEditorHtml(dataBg)).toBe(dataBg);
  });

  it("rejects CSS escapes, comments and non-allowlisted functions", () => {
    // A backslash escape spells url( without the literal text.
    expect(
      sanitizeEditorHtml('<div style="background:u\\72l(javascript:alert(1))">x</div>'),
    ).toBe("<div>x</div>");
    expect(
      sanitizeEditorHtml('<div style="background:\\75\\72\\6c(javascript:alert(1))">x</div>'),
    ).toBe("<div>x</div>");
    // A comment splits the token the same way.
    expect(
      sanitizeEditorHtml('<div style="background:u/**/rl(javascript:alert(1))">x</div>'),
    ).toBe("<div>x</div>");
    // URL-carrying functions are off the allowlist entirely.
    for (const css of [
      "background:image-set(url(javascript:alert(1)) 1x)",
      "background:-webkit-image-set(url(javascript:alert(1)) 1x)",
      "background:cross-fade(url(https://x.dev/a.png), url(javascript:x) 50%)",
      "background:paint(evil)",
      "list-style-image:image-set(url(javascript:alert(1)) 1x)",
    ]) {
      expect(sanitizeEditorHtml(`<div style="${css}">x</div>`), css).toBe("<div>x</div>");
    }
    // Gradient functions stay - email markup uses them for backgrounds.
    const grad =
      '<td style="background:linear-gradient(to right, rgb(1,2,3), #fff)">a</td>';
    expect(sanitizeEditorHtml(grad)).toBe(grad);
    // A quoted value that happens to look functional (a font name) still parses.
    const font = '<span style="font-family:\'Segoe (UI)\', sans-serif">x</span>';
    expect(sanitizeEditorHtml(font)).toBe(font);
  });

  it("keeps the links the composer makes, drops script and file URLs", () => {
    expect(sanitizeEditorHtml('<a href="mailto:a@b.c">m</a>')).toBe('<a href="mailto:a@b.c">m</a>');
    expect(sanitizeEditorHtml('<a href="tel:+15550100">t</a>')).toBe('<a href="tel:+15550100">t</a>');
    for (const href of [
      "javascript:alert(1)",
      "jav&#x61;script:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "file:///etc/passwd",
      "/relative/path",
      "#anchor",
    ]) {
      expect(sanitizeEditorHtml(`<a href="${href}">x</a>`), href).toBe("<a>x</a>");
    }
  });

  it("keeps raster data and cid images, drops svg/html data sources", () => {
    expect(
      sanitizeEditorHtml('<img src="data:image/jpeg;base64,/9j/" alt="pic">'),
    ).toBe('<img src="data:image/jpeg;base64,/9j/" alt="pic">');
    expect(sanitizeEditorHtml('<img src="data:image/svg+xml;base64,PHN2Zz4=">')).toBe("");
    expect(sanitizeEditorHtml('<img src="data:image/pngfoo;base64,AA=">')).toBe("");
    expect(sanitizeEditorHtml('<img src="data:text/html;base64,PHNjcmlwdD4=">')).toBe("");
    expect(sanitizeEditorHtml('<img src="cid:part1@x">')).toBe('<img src="cid:part1@x">');
    expect(sanitizeEditorHtml('<img src="javascript:alert(1)" onerror="x">ok')).toBe("ok");
  });

  it("drops scriptable and structural markup entirely", () => {
    expect(sanitizeEditorHtml("<b>Jane</b><script>alert(1)</script>")).toBe("<b>Jane</b>");
    expect(sanitizeEditorHtml("<style>b{color:red}</style>x")).toBe("x");
    expect(sanitizeEditorHtml('<iframe src="https://x.dev"><b>no</b></iframe>ok')).toBe("ok");
    expect(sanitizeEditorHtml("<object><b>no</b></object>ok")).toBe("ok");
    expect(sanitizeEditorHtml("<svg><text>no</text></svg>ok")).toBe("ok");
    expect(sanitizeEditorHtml("<math><mi>no</mi></math>ok")).toBe("ok");
    expect(sanitizeEditorHtml("<template><b>no</b></template>ok")).toBe("ok");
    // Form chrome unwraps (its children are kept as content); void inputs go.
    expect(sanitizeEditorHtml("<form><input value=a><button>Go</button>Jane</form>")).toBe("GoJane");
    expect(sanitizeEditorHtml('<meta charset="utf-8"><link href="x"><base href="x">ok')).toBe("ok");
    expect(sanitizeEditorHtml('<div onclick="x" onmouseover=y>Jane</div>')).toBe("<div>Jane</div>");
  });

  it("unwraps unknown wrappers instead of dropping content", () => {
    expect(sanitizeEditorHtml("<section><article>hi</article></section>")).toBe("hi");
    expect(sanitizeEditorHtml("<o:p>x</o:p><custom-tag a=1>y</custom-tag>")).toBe("xy");
    // A responsive-image wrapper goes, its kept <img> stays.
    expect(
      sanitizeEditorHtml('<picture><img src="https://x.dev/a.png"></picture>'),
    ).toBe('<img src="https://x.dev/a.png">');
    expect(
      sanitizeEditorHtml('<map name="m"><area href="https://x.dev">x</map><label>L</label><dialog open>D</dialog>'),
    ).toBe("xLD");
    // select is chrome whose content is not email content.
    expect(sanitizeEditorHtml("<select><option>a</option></select>ok")).toBe("ok");
  });

  it("keeps table markup from quoted mail", () => {
    const table =
      '<table cellpadding="0" cellspacing="0" border="0"><tbody>' +
      '<tr><td colspan="2" style="padding:4px">a</td></tr>' +
      '<tr><td>b</td><td>c</td></tr></tbody></table>';
    expect(sanitizeEditorHtml(table)).toBe(table);
  });

  it("is idempotent", () => {
    for (const html of [
      EDITOR_BODY,
      '<span class="co-mention" contenteditable="false" data-email="a@b.c">@A</span>',
      '<div style="color:red; font-size: 12px;">x &amp; y</div>',
      '<img src="https://x.dev/a.png?a=1&amp;b=2">',
      "<table><tr><td>a<td>b",
      '<div style="position:fixed;color:red">x</div>',
    ]) {
      const once = sanitizeEditorHtml(html);
      expect(sanitizeEditorHtml(once)).toBe(once);
    }
  });

  it("keeps browser-serialized editor output as fixed points", () => {
    // The shape innerHTML actually emits: lowercase tags, double-quoted
    // attributes, &amp; inside URLs, spaced declarations with a trailing ';'.
    for (const html of [
      '<div style="font-family: Arial, sans-serif; font-size: 12px;">x</div>',
      '<div style="color: rgb(18, 52, 86); text-align: center;">x</div>',
      '<a href="https://x.dev/?a=1&amp;b=2">x</a>',
      '<img src="https://x.dev/a.png?w=1&amp;h=2" alt="a &amp; b">',
      '<ul type="disc"><li>one</li></ul><ol start="2" type="a"><li>two</li></ol>',
      '<td style="padding: 4px; vertical-align: top;">a</td>',
      '<div dir="ltr" lang="en" align="center" bgcolor="#ffffff">x</div>',
      '<div>line<br>break &amp; entity</div>',
    ]) {
      expect(sanitizeEditorHtml(html), html).toBe(html);
    }
    // A foreign draft normalizes once: gmail class/id go, dir and <br> stay.
    expect(
      sanitizeEditorHtml(
        '<div class="gmail_default" dir="ltr">hi<br><div id="x">there</div></div>',
      ),
    ).toBe('<div dir="ltr">hi<br><div>there</div></div>');
  });

  it("caps nesting depth instead of growing the stack and the output", () => {
    const out = sanitizeEditorHtml("<div>".repeat(1000));
    // 256 opens survive, the rest unwrap; the depth the browser sees is
    // bounded either way.
    expect(out.match(/<div>/g)).toHaveLength(256);
    expect(out.match(/<\/div>/g)).toHaveLength(256);
    // Same-tag closes past the cap still close real opens.
    const shallow = sanitizeEditorHtml("<div>".repeat(300) + "</div>".repeat(300));
    expect(shallow.startsWith("<div>")).toBe(true);
    expect(shallow.endsWith("</div>")).toBe(true);
    expect((shallow.match(/<div>/g) ?? []).length).toBe(256);
    expect((shallow.match(/<\/div>/g) ?? []).length).toBe(256);
  });

  it("stays fast on pathological and large inputs", () => {
    const timed = (html: string, minLen = 100_000) => {
      expect(html.length).toBeGreaterThanOrEqual(minLen);
      const t0 = performance.now();
      sanitizeEditorHtml(html);
      expect(performance.now() - t0).toBeLessThan(1000);
    };
    // Unterminated-tag soup (was quadratic in the regex tokenizer).
    timed(`<div>${"<a ".repeat(12000)}x${"<b href=\"".repeat(12000)}`);
    // Deep same-tag nesting, then deep nesting + mismatched end tags
    // (was quadratic in the stack scans).
    timed("<div>".repeat(80_000), 400_000);
    timed(`${"<span>".repeat(30_000)}${"</b>".repeat(30_000)}`, 300_000);
    // Alternating implied closes, and a flood of unmatched end tags.
    timed("<p>x<div>".repeat(30_000), 200_000);
    timed("</b>".repeat(50_000), 200_000);
    // One tag with tens of thousands of attributes, one attribute of ~1 MB.
    timed(`<div ${Array.from({ length: 30_000 }, (_, i) => `a${i}="v"`).join(" ")}>x`);
    timed(`<div title="${"v".repeat(1_000_000)}">x`, 1_000_000);
    // A style attribute with tens of thousands of declarations.
    timed(`<div style="${"color:red;".repeat(30_000)}">x`, 300_000);
    // Ordinary well-formed mail HTML at multi-MB scale.
    timed(
      `<div>Hi <b>there</b>, <a href="https://x.dev">link</a><br></div>`.repeat(50_000),
      3_000_000,
    );
  });

  it("returns empty for empty input", () => {
    expect(sanitizeEditorHtml("")).toBe("");
  });
});
