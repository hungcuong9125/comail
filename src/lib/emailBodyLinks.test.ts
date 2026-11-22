import { describe, expect, it } from "vitest";
import { bodyLinkAction } from "./emailBodyLinks";

describe("bodyLinkAction", () => {
  it("opens http(s) and mailto links externally", () => {
    for (const href of [
      "https://example.com",
      "http://example.com/path?q=1",
      "HTTPS://example.com",
      "mailto:a@b.c",
      "  https://example.com  ",
    ]) {
      expect(bodyLinkAction(href), href).toBe("external");
    }
  });

  it("lets in-document anchors behave natively", () => {
    expect(bodyLinkAction("#quoted")).toBe("native");
    expect(bodyLinkAction("#")).toBe("native");
  });

  it("blocks every other href so it can never navigate", () => {
    for (const href of [
      "data:text/html,<h1>x</h1>",
      "data:image/png;base64,AAAA",
      "cid:logo@x",
      "javascript:alert(1)",
      "file:///etc/passwd",
      "tel:+15551234",
      "vbscript:x",
      "/relative/path",
      "relative.html",
      "//example.com",
      "about:blank",
      "",
      "   ",
      null,
      undefined,
    ]) {
      expect(bodyLinkAction(href), String(href)).toBe("block");
    }
  });
});
