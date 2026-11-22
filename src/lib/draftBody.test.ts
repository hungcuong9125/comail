import { describe, expect, it } from "vitest";
import { draftBodyForSave } from "./draftBody";

describe("draftBodyForSave", () => {
  it("strips scripts, event handlers, and javascript: links from the body", () => {
    const hostile =
      '<p>hi</p><img src="x" onerror="alert(1)">' +
      '<script>alert(2)</script>' +
      '<a href="javascript:alert(3)">click</a>';
    const { bodyHtml, bodyText } = draftBodyForSave(hostile, "", false);
    expect(bodyHtml).not.toContain("onerror");
    expect(bodyHtml).not.toContain("<script");
    expect(bodyHtml).not.toContain("javascript:");
    expect(bodyHtml).toContain("<p>hi</p>");
    expect(bodyHtml).toContain("click");
    expect(bodyText).not.toContain("onerror");
    expect(bodyText).toContain("hi");
  });

  it("is idempotent for already-clean editor output", () => {
    const clean = '<p>hello <b>world</b></p><img src="cid:att-1">';
    const once = draftBodyForSave(clean, "", false).bodyHtml;
    const twice = draftBodyForSave(once, "", false).bodyHtml;
    expect(twice).toBe(once);
  });

  it("keeps the wire quote out of bodyText-html and appends it plainly", () => {
    const { bodyText, bodyHtml } = draftBodyForSave(
      "<p>mine</p>",
      "On Tue, X wrote:\n> quoted line",
      false,
    );
    expect(bodyText.endsWith("On Tue, X wrote:\n> quoted line")).toBe(true);
    expect(bodyHtml).toContain("<blockquote>");
    expect(bodyHtml).toContain("<p>mine</p>");
  });

  it("drops the quote entirely when the user removed it", () => {
    const { bodyText, bodyHtml } = draftBodyForSave("<p>mine</p>", "On Tue…", true);
    expect(bodyHtml).not.toContain("blockquote");
    expect(bodyText).not.toContain("On Tue");
  });
});
