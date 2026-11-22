import { escapeHtml, htmlToText, textToHtml } from "./richtext";
import { stripQuoteMarkers } from "./quotes";
import { sanitizeEditorHtml } from "./signatures";

/** The plain-text wire quote rendered as HTML: attribution line + blockquote. */
export function quoteToHtml(quoteText: string): string {
  const lines = quoteText.split("\n");
  const header = lines[0] ?? "";
  const rest = stripQuoteMarkers(lines.slice(1).join("\n"));
  return `<div>${escapeHtml(header)}</div><blockquote>${textToHtml(rest)}</blockquote>`;
}

/**
 * Build the bodyText/bodyHtml pair persisted by save_draft (and therefore
 * sent). The rich body is sanitized HERE, not only in the editor's DOM:
 * the composer can hold markup that never round-tripped through the editor
 * (a loaded draft, a reply/forward prefill, AI output) and a send without
 * typing would otherwise emit it raw. sanitizeEditorHtml is idempotent and
 * linear, so the extra pass over the assembled HTML costs a few ms even for
 * multi-MB bodies with inline images.
 */
export function draftBodyForSave(
  bodyHtml: string,
  quote: string,
  quoteRemoved: boolean,
): { bodyText: string; bodyHtml: string } {
  const cleanBody = sanitizeEditorHtml(bodyHtml);
  const plain = htmlToText(cleanBody);
  const withQuote = quote !== "" && !quoteRemoved;
  return {
    bodyText: withQuote ? `${plain.replace(/\s+$/, "")}\n\n${quote}` : plain,
    bodyHtml: sanitizeEditorHtml(
      withQuote ? `${cleanBody}<br><br>${quoteToHtml(quote)}` : cleanBody,
    ),
  };
}
