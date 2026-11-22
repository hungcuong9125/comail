import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react";
import { useTranslation } from "react-i18next";
import { captureOutsideSelection } from "../../lib/selection";
import { stripFormatting, textToHtml } from "../../lib/richtext";
import { EDITOR_IMAGE_TYPES, sanitizeEditorHtml } from "../../lib/signatures";
import { activeMention } from "../../lib/mentions";
import { addressName, IS_MAC } from "../../lib/format";
import { call } from "../../ipc/commands";
import { useUi } from "../../stores/ui";
import type { Address } from "../../ipc/types";
import { Button } from "../ui/Button";

export interface RichBodyHandle {
  focus(): void;
  /** Focus with the caret at the very start (replies: type above the quote). */
  focusStart(): void;
  /** Insert plain text at the caret (snippet browser). */
  insertText(text: string): void;
  /** Insert an HTML fragment at the caret (availability slots). */
  insertHtml(html: string): void;
}

/** Insert `html` at the current selection: execCommand where the engine
 *  allows it (keeps ⌘Z), a manual Range insert otherwise. The fragment must
 *  already be sanitized. */
function insertFragmentAtSelection(sel: Selection, html: string) {
  if (sel.rangeCount === 0) return;
  if (!document.execCommand("insertHTML", false, html)) {
    const range = sel.getRangeAt(0);
    range.deleteContents();
    const tpl = document.createElement("template");
    tpl.innerHTML = html;
    const last = tpl.content.lastChild;
    range.insertNode(tpl.content);
    const after = document.createRange();
    if (last) after.setStartAfter(last);
    else after.setStart(range.startContainer, range.startOffset);
    after.collapse(true);
    sel.removeAllRanges();
    sel.addRange(after);
  }
}

/** Replace `range` with `text` (newlines become <br>) and collapse the selection
 *  just after the inserted content. Engine-independent - the Range API works
 *  reliably in WebKitGTK where a programmatic execCommand("insertText") can be a
 *  silent no-op. */
function replaceRangeWithText(range: Range, sel: Selection, text: string) {
  range.deleteContents();
  const frag = document.createDocumentFragment();
  text.split("\n").forEach((part, i) => {
    if (i > 0) frag.appendChild(document.createElement("br"));
    frag.appendChild(document.createTextNode(part));
  });
  const last = frag.lastChild;
  range.insertNode(frag);
  const after = document.createRange();
  if (last?.nodeType === Node.TEXT_NODE) {
    after.setStart(last, last.textContent?.length ?? 0);
  } else if (last) {
    after.setStartAfter(last);
  } else {
    after.setStart(range.startContainer, range.startOffset);
  }
  after.collapse(true);
  sel.removeAllRanges();
  sel.addRange(after);
}

type Cmd =
  | "bold"
  | "italic"
  | "underline"
  | "strikeThrough"
  | "insertUnorderedList"
  | "insertOrderedList";

/** Rich-text editing surface for the composer and the signature editor: a
 *  contenteditable div with a formatting toolbar (bold/italic/underline/strike,
 *  lists, quote, inline images, links). The parent owns the HTML string;
 *  external changes (AI draft, quick replies, signature) are synced in without
 *  disturbing typing. */
export const RichBody = forwardRef<
  RichBodyHandle,
  {
    value: string;
    onChange: (html: string) => void;
    placeholder: string;
    minHeightClass: string;
    /** ";shortcut " typed inline: return the replacement text, or null. */
    expandShortcut?: (shortcut: string) => string | null;
    /** A colleague picked from the "@" mention menu - add them as a recipient. */
    onMention?: (a: Address) => void;
    /** Fired after the editor loses focus and its latest HTML is emitted. */
    onBlur?: () => void;
  }
>(function RichBody(
  { value, onChange, placeholder, minHeightClass, expandShortcut, onMention, onBlur },
  ref,
) {
  const { t } = useTranslation();
  const elRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  // The HTML the parent last heard from us (or what the DOM last synced to) -
  // doubles as emit() dedup and the "this value is our own emission" check.
  const lastEmittedRef = useRef("");
  // The last external `value` prop the DOM was synced from. Sanitizing applies
  // only to those external values; our own emissions are already clean and
  // echoed back through `value`, which must not trigger another pass.
  const consumedValueRef = useRef<string | null>(null);
  // Composer hands down a fresh inline callback each render; a ref keeps the
  // sync effect's deps stable without going stale.
  const onChangeRef = useRef(onChange);
  useEffect(() => {
    onChangeRef.current = onChange;
  }, [onChange]);
  // Selection captured when a popover opens (inputs steal focus, so we restore
  // the editor's range before applying the command).
  const savedRangeRef = useRef<Range | null>(null);
  // Set by cmd/ctrl+shift+V so the paste that follows drops its formatting.
  const pastePlainRef = useRef(false);
  // A drag that starts inside this editor is a native move, not incoming
  // content: flag it so onDrop lets the browser relocate the source instead
  // of sanitizing a duplicate in at the drop point.
  const internalDragRef = useRef(false);
  // One scheduled re-check of the DOM after an event the browser handled
  // itself (native move, plain-text paste). See scheduleDomCheck.
  const domCheckRef = useRef<number | null>(null);
  const [empty, setEmpty] = useState(true);
  const [active, setActive] = useState<Record<string, boolean>>({});
  const [linkOpen, setLinkOpen] = useState(false);
  const [linkUrl, setLinkUrl] = useState("");
  // "@" mention menu: the token being typed (with its caret anchor) plus the
  // colleague matches and the highlighted row. Null when no mention is active.
  const [mention, setMention] = useState<{
    query: string;
    startNode: Text;
    startOffset: number;
    left: number;
    top: number;
  } | null>(null);
  const [hits, setHits] = useState<Address[]>([]);
  const [mentionCursor, setMentionCursor] = useState(0);
  // Open only once we actually have colleagues to show (a bare "@" matches none).
  const mentionOpen = mention != null && hits.length > 0;

  const refreshEmpty = useCallback((el: HTMLDivElement) => {
    setEmpty(el.textContent?.trim() === "" && !el.querySelector("img"));
  }, []);

  // Sync EXTERNAL value -> DOM: drafts, AI output, quick-reply inserts. A
  // `value` that is our own last emission (echoed back through the parent) or
  // the external value already synced in needs no pass at all - the DOM is
  // the source for it, and every insertion path sanitizes on the way in, so
  // the allowlist never sees self-produced content.
  useEffect(() => {
    const el = elRef.current;
    if (!el) return;
    if (value === lastEmittedRef.current || value === consumedValueRef.current) return;
    consumedValueRef.current = value;
    const clean = sanitizeEditorHtml(value);
    if (el.innerHTML === clean) return;
    el.innerHTML = clean;
    refreshEmpty(el);
    // The sanitized DOM is the new baseline: emit() compares against it, and
    // no onChange fires for the load-time normalization - the parent marking
    // the composer dirty on a draft open must only come from a real edit.
    lastEmittedRef.current = el.innerHTML;
  }, [value, refreshEmpty]);

  const emit = useCallback(() => {
    const el = elRef.current;
    if (!el || el.innerHTML === lastEmittedRef.current) return;
    lastEmittedRef.current = el.innerHTML;
    consumedValueRef.current = el.innerHTML;
    refreshEmpty(el);
    onChangeRef.current(el.innerHTML);
  }, [refreshEmpty]);

  // The internal-drag flag can stay set if dragend never reaches the editor
  // (the dragged source node was removed mid-drag, or the drop left the
  // window). Rather than trusting the flag alone: any drop or paste the
  // browser performs natively is followed by a next-frame check that
  // re-sanitizes the DOM and emits if the cleanup changed anything.
  const scheduleDomCheck = useCallback(() => {
    if (domCheckRef.current != null) return;
    domCheckRef.current = window.setTimeout(() => {
      domCheckRef.current = null;
      const el = elRef.current;
      if (!el) return;
      const clean = sanitizeEditorHtml(el.innerHTML);
      if (clean !== el.innerHTML) {
        // Caret as (child-index path, offset) pairs from the editor root, so
        // it survives the innerHTML rewrite as well as it can.
        const sel = document.getSelection();
        const r = sel && sel.rangeCount ? sel.getRangeAt(0) : null;
        const pathOf = (node: Node, offset: number): number[] | null => {
          const p = [offset];
          let n: Node | null = node;
          while (n && n !== el) {
            const parent: Node | null = n.parentNode;
            if (!parent) return null;
            p.unshift(Array.prototype.indexOf.call(parent.childNodes, n));
            n = parent;
          }
          return n === el ? p : null;
        };
        const start = r && el.contains(r.startContainer) ? pathOf(r.startContainer, r.startOffset) : null;
        const end = r && el.contains(r.endContainer) ? pathOf(r.endContainer, r.endOffset) : null;
        el.innerHTML = clean;
        if (sel && start && end) {
          const resolve = (p: number[]) => {
            let node: Node = el;
            for (let k = 0; k < p.length - 1; k += 1) {
              const next = node.childNodes[p[k]];
              if (!next) return null;
              node = next;
            }
            const max =
              node.nodeType === Node.TEXT_NODE
                ? (node.textContent ?? "").length
                : node.childNodes.length;
            return { node, offset: Math.min(p[p.length - 1], max) };
          };
          const a = resolve(start);
          const b = resolve(end);
          if (a && b) sel.setBaseAndExtent(a.node, a.offset, b.node, b.offset);
        }
      }
      emit();
    }, 0);
  }, [emit]);

  // A stale internal-drag flag is also cleared directly when a new drag
  // starts outside the editor or the window loses focus mid-drag.
  useEffect(() => {
    const onDocDragStart = (e: DragEvent) => {
      const el = elRef.current;
      if (!el || !el.contains(e.target as Node)) internalDragRef.current = false;
    };
    const onWindowBlur = () => {
      internalDragRef.current = false;
    };
    document.addEventListener("dragstart", onDocDragStart, true);
    window.addEventListener("blur", onWindowBlur);
    return () => {
      document.removeEventListener("dragstart", onDocDragStart, true);
      window.removeEventListener("blur", onWindowBlur);
    };
  }, []);

  /**
   * "Convert to plain text": drop the formatting of the selection, or of the
   * whole body when nothing is selected. execCommand("removeFormat") only
   * unwraps inline styling, so the structural markup (tables, lists, quotes,
   * headings, pasted <div> soup) is flattened by re-serialising the range
   * through `stripFormatting`, which keeps text, images, mention chips and
   * links.
   */
  const clearFormatting = useCallback(() => {
    const el = elRef.current;
    if (!el) return;
    el.focus();
    const sel = document.getSelection();
    if (!sel) return;
    const range =
      sel.rangeCount && el.contains(sel.anchorNode) ? sel.getRangeAt(0) : null;

    const all = document.createRange();
    all.selectNodeContents(el);
    // Nothing selected, or a selection covering everything: take the whole
    // body, so any block wrapper the content sits in goes too.
    const whole =
      !range ||
      range.collapsed ||
      (range.compareBoundaryPoints(Range.START_TO_START, all) <= 0 &&
        range.compareBoundaryPoints(Range.END_TO_END, all) >= 0);
    if (whole) {
      sel.removeAllRanges();
      sel.addRange(all);
    } else {
      // Unwrap the inline formatting first: it splits the <b>/<span> the
      // selection sits inside, so the flattened text isn't re-inserted into a
      // still-styled parent.
      document.execCommand("removeFormat", false);
    }

    const live = sel.rangeCount ? sel.getRangeAt(0) : all;
    const holder = document.createElement("div");
    holder.appendChild(live.cloneContents());
    const html = stripFormatting(holder.innerHTML);
    // insertHTML rather than a DOM swap, so ⌘Z still undoes the whole thing.
    if (!document.execCommand("insertHTML", false, html || "<br>")) {
      const tpl = document.createElement("template");
      tpl.innerHTML = html;
      const last = tpl.content.lastChild;
      live.deleteContents();
      live.insertNode(tpl.content);
      const after = document.createRange();
      if (last) after.setStartAfter(last);
      else after.setStart(live.startContainer, live.startOffset);
      after.collapse(true);
      sel.removeAllRanges();
      sel.addRange(after);
    }
    refreshActive();
    emit();
  }, [emit]);

  const exec = useCallback(
    (cmd: Cmd | "blockquote" | "image" | "clearFormat") => {
      const el = elRef.current;
      if (!el) return;
      if (cmd === "clearFormat") {
        clearFormatting();
        return;
      }
      // Text selected in the thread above (message body or its iframe) wins:
      // "select part of the previous email, press quote" inserts it as a
      // quotation. Read before focus() - focusing moves the doc selection.
      const outside = cmd === "blockquote" ? captureOutsideSelection(el) : null;
      el.focus();
      if (cmd === "image") {
        fileRef.current?.click();
        return;
      }
      if (cmd === "blockquote") {
        if (outside) {
          // focus() alone leaves the document selection on the (non-editable)
          // message text, where insertHTML is a no-op - move the caret into
          // the editor first (keep it if it's already there, else go to end).
          const sel = document.getSelection();
          if (sel && (!sel.anchorNode || !el.contains(sel.anchorNode))) {
            const range = document.createRange();
            range.selectNodeContents(el);
            range.collapse(false);
            sel.removeAllRanges();
            sel.addRange(range);
          }
          document.execCommand(
            "insertHTML",
            false,
            `<blockquote>${textToHtml(outside)}</blockquote><div><br></div>`,
          );
          refreshActive();
          emit();
          return;
        }
        const cur = document.queryCommandValue("formatBlock").toLowerCase();
        // Angle brackets: the only form WebKit and Gecko both accept.
        document.execCommand(
          "formatBlock",
          false,
          cur === "blockquote" ? "<div>" : "<blockquote>",
        );
      } else {
        document.execCommand(cmd, false);
      }
      refreshActive();
      emit();
    },
    [emit, clearFormatting],
  );

  /** Formatting keyboard shortcuts (⌘/Ctrl + B, I, U, …). WebKitGTK, which the
   *  Linux build runs on, ships no default editing keybindings for a
   *  contenteditable, and the app's global registry would otherwise swallow the
   *  combos (⌘K opens the palette). So bind them here and stop the event. */
  const handleShortcut = (e: React.KeyboardEvent): boolean => {
    const mod = e.metaKey || e.ctrlKey;
    if (!mod || e.altKey) return false;
    // Layout independent where possible: `code` keeps ⌘⇧7 working on layouts
    // where shift+7 is not "&".
    const code = (e.nativeEvent as KeyboardEvent).code;
    const key = e.key.toLowerCase();

    let cmd: Cmd | "blockquote" | null = null;
    if (!e.shiftKey) {
      if (key === "b") cmd = "bold";
      else if (key === "i") cmd = "italic";
      else if (key === "u") cmd = "underline";
      else if (key === "k") {
        openLink();
        return true;
      } else if (key === "z") {
        // Without this the global registry's ⌘Z would undo the last triage
        // action instead of the last thing typed here.
        document.execCommand("undo", false);
        refreshActive();
        emit();
        return true;
      } else if (key === "\\" || code === "Backslash") {
        clearFormatting();
        return true;
      }
    } else if (key === "v") {
      // ⌘⇧V: let the paste through, but strip its formatting (below).
      pastePlainRef.current = true;
      window.setTimeout(() => {
        pastePlainRef.current = false;
      }, 500);
      return false;
    } else {
      // Shifted combos, matching Gmail: ⌘⇧X strike, ⌘⇧7/8 lists, ⌘⇧9 quote.
      if (key === "x") cmd = "strikeThrough";
      else if (code === "Digit7" || key === "7") cmd = "insertOrderedList";
      else if (code === "Digit8" || key === "8") cmd = "insertUnorderedList";
      else if (code === "Digit9" || key === "9") cmd = "blockquote";
    }
    if (!cmd) return false;
    exec(cmd);
    return true;
  };

  const refreshActive = () => {
    setActive({
      bold: document.queryCommandState("bold"),
      italic: document.queryCommandState("italic"),
      underline: document.queryCommandState("underline"),
      strikeThrough: document.queryCommandState("strikeThrough"),
      insertUnorderedList: document.queryCommandState("insertUnorderedList"),
      insertOrderedList: document.queryCommandState("insertOrderedList"),
      blockquote: document.queryCommandValue("formatBlock").toLowerCase() === "blockquote",
    });
  };

  // Toolbar states follow the caret; also remember the last in-editor caret so
  // insertions made while focus is elsewhere (snippet picker, quick replies)
  // land where the user actually was rather than at the end.
  useEffect(() => {
    const handler = () => {
      const el = elRef.current;
      const sel = document.getSelection();
      if (!el || !sel?.anchorNode || !el.contains(sel.anchorNode)) return;
      if (sel.rangeCount) savedRangeRef.current = sel.getRangeAt(0).cloneRange();
      refreshActive();
    };
    document.addEventListener("selectionchange", handler);
    return () => document.removeEventListener("selectionchange", handler);
  }, []);

  /** Focus the editor and guarantee a selection range *inside* it, so an
   *  insertion has somewhere to land. When called after focus has been elsewhere
   *  (snippet picker, quick-reply button), WebKit leaves the selection outside
   *  the element; restore the user's last caret, or fall back to the end of the
   *  content. Returns false if the element is gone. */
  const ensureCaret = (): boolean => {
    const el = elRef.current;
    if (!el) return false;
    el.focus();
    const sel = document.getSelection();
    if (!sel) return false;
    if (sel.rangeCount > 0 && el.contains(sel.anchorNode)) return true;
    const saved = savedRangeRef.current;
    const range = document.createRange();
    if (saved && el.contains(saved.startContainer)) {
      // Restore the last caret the user had before focus moved away.
      range.setStart(saved.startContainer, saved.startOffset);
      range.setEnd(saved.endContainer, saved.endOffset);
    } else {
      // Stale/absent: fall back to the end of the content.
      range.selectNodeContents(el);
      range.collapse(false);
    }
    sel.removeAllRanges();
    sel.addRange(range);
    return true;
  };

  useImperativeHandle(ref, () => ({
    focus: () => elRef.current?.focus(),
    focusStart: () => {
      const el = elRef.current;
      if (!el) return;
      el.focus();
      const sel = document.getSelection();
      if (sel) {
        const range = document.createRange();
        range.setStart(el, 0);
        range.collapse(true);
        sel.removeAllRanges();
        sel.addRange(range);
      }
    },
    insertText: (text: string) => {
      if (!ensureCaret()) return;
      const sel = document.getSelection();
      if (!sel || sel.rangeCount === 0) return;
      replaceRangeWithText(sel.getRangeAt(0), sel, text);
      emit();
    },
    insertHtml: (html: string) => {
      if (!ensureCaret()) return;
      const sel = document.getSelection();
      if (!sel || sel.rangeCount === 0) return;
      const range = sel.getRangeAt(0);
      range.deleteContents();
      const tpl = document.createElement("template");
      tpl.innerHTML = sanitizeEditorHtml(html);
      const last = tpl.content.lastChild;
      range.insertNode(tpl.content);
      const after = document.createRange();
      if (last) after.setStartAfter(last);
      else after.setStart(range.startContainer, range.startOffset);
      after.collapse(true);
      sel.removeAllRanges();
      sel.addRange(after);
      emit();
    },
  }));

  /**
   * ";shortcut" typed at the caret expands in place. A trailing space/nbsp
   * triggers it while typing; pressing Enter or Tab (`atCaretEnd`) commits the
   * shortcut sitting right before the caret with no separator. Returns true
   * when an expansion happened so callers can swallow the key.
   */
  const maybeExpandSnippet = (atCaretEnd = false): boolean => {
    if (!expandShortcut) return false;
    const el = elRef.current;
    const sel = document.getSelection();
    if (!el || !sel || !sel.isCollapsed || sel.rangeCount === 0) return false;

    // Resolve the caret to a text node + offset. On replies, focusStart leaves an
    // element-level caret and WebKit keeps anchorNode on the contenteditable div
    // rather than the text node - descend into the preceding text child so the
    // shortcut is still seen.
    let node = sel.anchorNode;
    let offset = sel.anchorOffset;
    if (node && node.nodeType === Node.ELEMENT_NODE) {
      const child = node.childNodes[offset - 1];
      if (child && child.nodeType === Node.TEXT_NODE) {
        node = child;
        offset = child.textContent?.length ?? 0;
      }
    }
    if (!node || node.nodeType !== Node.TEXT_NODE || !el.contains(node)) return false;

    // Text leading up to the caret. WebKit splits a line into adjacent text
    // nodes around IME commits (Vietnamese input) and nbsp insertion, so the
    // ";", the shortcut, and the separator may each live in a different node \u2014
    // walk preceding text siblings instead of reading only the caret's node.
    const chain: Text[] = [node as Text];
    let upto = (node.textContent ?? "").slice(0, offset);
    for (
      let prev = node.previousSibling;
      prev?.nodeType === Node.TEXT_NODE && upto.length < 80;
      prev = prev.previousSibling
    ) {
      chain.unshift(prev as Text);
      upto = (prev.textContent ?? "") + upto;
    }

    const m = (atCaretEnd ? /;([a-z0-9_-]+)()$/i : /;([a-z0-9_-]+)([ \u00a0])$/i).exec(upto);
    if (!m) return false;
    const replacement = expandShortcut(m[1]);
    if (replacement == null) return false;

    // Map the match start back onto a (text node, offset) pair \u2014 it may sit
    // in an earlier node than the caret's.
    let startIdx = upto.length - m[0].length;
    let startNode: Text = node as Text;
    for (const part of chain) {
      const len = part === node ? offset : (part.textContent?.length ?? 0);
      if (startIdx <= len) {
        startNode = part;
        break;
      }
      startIdx -= len;
    }

    // Replace ";shortcut<sep>" in place, keeping the trailing separator.
    const range = document.createRange();
    range.setStart(startNode, startIdx);
    range.setEnd(node, offset);
    replaceRangeWithText(range, sel, replacement + m[2]);
    emit();
    return true;
  };

  const closeMention = () => setMention(null);

  /**
   * Detect an "@name" the user is typing at the caret and open the colleague
   * menu. Mirrors maybeExpandSnippet's caret walk (WebKit splits a line into
   * adjacent text nodes around IME commits, so we read across preceding text
   * siblings), then hands the leading text to `activeMention`.
   */
  const detectMention = () => {
    const el = elRef.current;
    const sel = document.getSelection();
    if (!el || !sel || !sel.isCollapsed || sel.rangeCount === 0) return closeMention();

    let node = sel.anchorNode;
    let offset = sel.anchorOffset;
    if (node && node.nodeType === Node.ELEMENT_NODE) {
      const child = node.childNodes[offset - 1];
      if (child && child.nodeType === Node.TEXT_NODE) {
        node = child;
        offset = child.textContent?.length ?? 0;
      }
    }
    if (!node || node.nodeType !== Node.TEXT_NODE || !el.contains(node)) return closeMention();

    const chain: Text[] = [node as Text];
    let upto = (node.textContent ?? "").slice(0, offset);
    for (
      let prev = node.previousSibling;
      prev?.nodeType === Node.TEXT_NODE && upto.length < 80;
      prev = prev.previousSibling
    ) {
      chain.unshift(prev as Text);
      upto = (prev.textContent ?? "") + upto;
    }

    const match = activeMention(upto);
    if (!match) return closeMention();

    // Map the "@" index back onto a (text node, offset) pair - it may sit in an
    // earlier node than the caret's.
    let idx = match.at;
    let startNode: Text = node as Text;
    for (const part of chain) {
      const len = part === node ? offset : (part.textContent?.length ?? 0);
      if (idx <= len) {
        startNode = part;
        break;
      }
      idx -= len;
    }

    // Anchor the menu just under the caret. A collapsed range can report an
    // empty rect in WebKit; fall back to the editor's left edge / bottom.
    const rects = sel.getRangeAt(0).getClientRects();
    const r = rects[0] ?? sel.getRangeAt(0).getBoundingClientRect();
    const elRect = el.getBoundingClientRect();
    const left = r.left || elRect.left;
    const top = (r.bottom || elRect.bottom) + 2;
    setMention({ query: match.query, startNode, startOffset: idx, left, top });
  };

  // Debounced colleague lookup for the active mention (same source and cadence
  // as the recipient field's autocomplete).
  useEffect(() => {
    if (!mention) {
      setHits([]);
      return;
    }
    let cancelled = false;
    const id = setTimeout(() => {
      void call("list_contacts", { prefix: mention.query, limit: 6 }).then((res) => {
        if (!cancelled) {
          setHits(res);
          setMentionCursor(0);
        }
      });
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(id);
    };
  }, [mention?.query]);

  /** Replace the typed "@query" with an atomic mention chip and add the
   *  colleague to the recipients. */
  const insertMention = (a: Address) => {
    const el = elRef.current;
    const m = mention;
    if (!el || !m) return;
    const sel = document.getSelection();
    if (!sel || sel.rangeCount === 0) {
      closeMention();
      return;
    }
    const caret = sel.getRangeAt(0);
    const range = document.createRange();
    range.setStart(m.startNode, m.startOffset);
    range.setEnd(caret.endContainer, caret.endOffset);
    range.deleteContents();

    const chip = document.createElement("span");
    chip.className = "co-mention";
    chip.setAttribute("contenteditable", "false");
    chip.setAttribute("data-email", a.email);
    chip.textContent = `@${addressName(a)}`;
    const space = document.createTextNode(" ");
    const frag = document.createDocumentFragment();
    frag.appendChild(chip);
    frag.appendChild(space);
    range.insertNode(frag);

    const after = document.createRange();
    after.setStartAfter(space);
    after.collapse(true);
    sel.removeAllRanges();
    sel.addRange(after);

    closeMention();
    onMention?.(a);
    emit();
  };

  const insertImageFile = (file: File): boolean => {
    // Only the raster types the editor allowlist accepts as data: sources.
    // An SVG/TIFF/HEIC insert would be stripped by the next sanitizing pass
    // (reopened draft), so refuse it here instead of losing it silently.
    if (!EDITOR_IMAGE_TYPES.has(file.type)) {
      useUi.getState().pushToast({
        kind: "error",
        message: t("compose:couldntPickFiles", { error: file.name || file.type }),
      });
      return false;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const el = elRef.current;
      if (!el || typeof reader.result !== "string") return;
      el.focus();
      document.execCommand("insertImage", false, reader.result);
      emit();
    };
    reader.readAsDataURL(file);
    return true;
  };

  /** Snapshot the current editor selection before a popover steals focus. */
  const saveSelection = () => {
    const sel = document.getSelection();
    const el = elRef.current;
    savedRangeRef.current =
      sel && sel.rangeCount && el?.contains(sel.anchorNode) ? sel.getRangeAt(0).cloneRange() : null;
  };

  /** Refocus the editor and re-apply the saved selection. */
  const restoreSelection = () => {
    const el = elRef.current;
    if (!el) return;
    el.focus();
    const range = savedRangeRef.current;
    if (range) {
      const sel = document.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
    }
  };

  /** Existing anchor href at the caret, for prefilling the link popover. */
  const currentLinkHref = (): string => {
    const sel = document.getSelection();
    let node: Node | null = sel?.anchorNode ?? null;
    while (node && node !== elRef.current) {
      if (node instanceof HTMLAnchorElement) return node.getAttribute("href") ?? "";
      node = node.parentNode;
    }
    return "";
  };

  const openLink = () => {
    saveSelection();
    setLinkUrl(currentLinkHref());
    setLinkOpen(true);
  };

  const applyLink = () => {
    const raw = linkUrl.trim();
    restoreSelection();
    if (raw) {
      // Only the schemes the link allowlist keeps: a relative "/path" or
      // bare "#anchor" href is meaningless to a mail recipient (and would be
      // stripped anyway), so anything else gets the https:// prefix as before.
      const href = /^(https?:|mailto:|tel:)/i.test(raw) ? raw : `https://${raw}`;
      const sel = document.getSelection();
      if (sel && sel.isCollapsed && sel.rangeCount) {
        // Build the anchor as a node: outerHTML serializes both the attribute
        // and the text safely, so the URL can't break out of its quotes.
        const a = document.createElement("a");
        a.setAttribute("href", href);
        a.textContent = href;
        if (!document.execCommand("insertHTML", false, a.outerHTML)) {
          const range = sel.getRangeAt(0);
          range.insertNode(a);
          range.setStartAfter(a);
          range.collapse(true);
          sel.removeAllRanges();
          sel.addRange(range);
        }
      } else {
        document.execCommand("createLink", false, href);
      }
    } else {
      document.execCommand("unlink", false);
    }
    setLinkOpen(false);
    emit();
  };

  // Tooltips carry the shortcut, so the bindings are discoverable.
  const M = IS_MAC ? "⌘" : "Ctrl+";
  const S = IS_MAC ? "⇧" : "Shift+";
  const buttons: {
    cmd: Cmd | "blockquote" | "image" | "clearFormat";
    label: React.ReactNode;
    title: string;
    hint?: string;
  }[] = [
    { cmd: "bold", label: <span className="font-bold">B</span>, title: t("compose:fmt.bold"), hint: `${M}B` },
    { cmd: "italic", label: <span className="italic">I</span>, title: t("compose:fmt.italic"), hint: `${M}I` },
    { cmd: "underline", label: <span className="underline">U</span>, title: t("compose:fmt.underline"), hint: `${M}U` },
    { cmd: "strikeThrough", label: <span className="line-through">S</span>, title: t("compose:fmt.strike"), hint: `${M}${S}X` },
    {
      cmd: "insertUnorderedList",
      label: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <line x1="9" y1="6" x2="20" y2="6" /><line x1="9" y1="12" x2="20" y2="12" /><line x1="9" y1="18" x2="20" y2="18" />
          <circle cx="4.5" cy="6" r="1" fill="currentColor" /><circle cx="4.5" cy="12" r="1" fill="currentColor" /><circle cx="4.5" cy="18" r="1" fill="currentColor" />
        </svg>
      ),
      title: t("compose:fmt.bullets"),
      hint: `${M}${S}8`,
    },
    {
      cmd: "blockquote",
      label: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
          <path d="M6 17h3l2-4V7H5v6h3zm8 0h3l2-4V7h-6v6h3z" />
        </svg>
      ),
      title: t("compose:fmt.quote"),
      hint: `${M}${S}9`,
    },
    {
      cmd: "image",
      label: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="3" y="3" width="18" height="18" rx="2" /><circle cx="8.5" cy="8.5" r="1.5" fill="currentColor" stroke="none" /><path d="M21 15l-5-5L5 21" />
        </svg>
      ),
      title: t("compose:fmt.image"),
    },
    {
      cmd: "clearFormat",
      // "Tx": the usual mark for stripping formatting.
      label: (
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
          <path d="M3 6V5h11v1" /><path d="M8.5 5v14" /><path d="M6 19h5" />
          <path d="M15.5 11.5l6 7" /><path d="M21.5 11.5l-6 7" />
        </svg>
      ),
      title: t("compose:fmt.clear"),
      hint: `${M}\\`,
    },
  ];

  return (
    <div className="flex min-h-0 flex-col">
      {/* toolbar */}
      <div className="relative flex items-center gap-0.5 pt-2 pb-1" data-testid="fmt-toolbar">
        {buttons.map((b) => (
          <button
            key={b.cmd}
            type="button"
            tabIndex={-1}
            title={b.hint ? `${b.title} (${b.hint})` : b.title}
            aria-label={b.title}
            // mousedown, so the editor selection is never lost
            onMouseDown={(e) => {
              e.preventDefault();
              exec(b.cmd);
            }}
            className={`flex size-6.5 items-center justify-center rounded-control text-sm transition-colors ${
              active[b.cmd]
                ? "bg-accent/15 text-accent"
                : "text-ink-faint hover:bg-bg2 hover:text-ink"
            }`}
          >
            {b.label}
          </button>
        ))}

        {/* link */}
        <button
          type="button"
          tabIndex={-1}
          title={`${t("compose:fmt.link")} (${M}K)`}
          aria-label={t("compose:fmt.link")}
          data-testid="fmt-link"
          onMouseDown={(e) => {
            e.preventDefault();
            openLink();
          }}
          className={`flex size-6.5 items-center justify-center rounded-control transition-colors ${
            linkOpen ? "bg-accent/15 text-accent" : "text-ink-faint hover:bg-bg2 hover:text-ink"
          }`}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1" />
            <path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1" />
          </svg>
        </button>

        {linkOpen && (
          <div
            className="co-pop-in absolute top-9 left-0 z-20 flex items-center gap-1.5 rounded-card border border-hairline bg-bg1 p-1 shadow-elev-2"
            data-testid="link-popover"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <input
              autoFocus
              value={linkUrl}
              onChange={(e) => setLinkUrl(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") { e.preventDefault(); applyLink(); }
                else if (e.key === "Escape") { e.preventDefault(); setLinkOpen(false); }
              }}
              placeholder={t("compose:fmt.linkPlaceholder")}
              className="h-7 w-56 rounded-control border border-hairline bg-bg0 px-2 text-base text-ink outline-none focus:border-accent"
            />
            <Button
              variant="primary"
              size="sm"
              onMouseDown={(e) => { e.preventDefault(); applyLink(); }}
            >
              {t("compose:fmt.linkApply")}
            </Button>
          </div>
        )}

      </div>

      <div
        ref={elRef}
        contentEditable
        role="textbox"
        aria-multiline="true"
        aria-label={placeholder}
        data-testid="rich-body"
        data-empty={empty}
        spellCheck
        className={`co-richbody ${minHeightClass} w-full flex-1 py-2 text-[14px] leading-relaxed text-ink outline-none select-text`}
        data-placeholder={placeholder}
        onMouseDown={() => {
          if (linkOpen) setLinkOpen(false);
        }}
        onKeyDown={(e) => {
          // Formatting combos win over everything (and over the global
          // registry: stopPropagation keeps ⌘K out of the command palette).
          if (handleShortcut(e)) {
            e.preventDefault();
            e.stopPropagation();
            return;
          }
          // The "@" mention menu grabs navigation keys first (before the snippet
          // Enter/Tab handling and the editor's own newline/caret moves).
          if (mentionOpen && !(e.nativeEvent as KeyboardEvent).isComposing) {
            if (e.key === "ArrowDown") {
              e.preventDefault();
              setMentionCursor((c) => Math.min(hits.length - 1, c + 1));
              return;
            }
            if (e.key === "ArrowUp") {
              e.preventDefault();
              setMentionCursor((c) => Math.max(0, c - 1));
              return;
            }
            if (e.key === "Enter" || e.key === "Tab") {
              e.preventDefault();
              insertMention(hits[mentionCursor]);
              return;
            }
            if (e.key === "Escape") {
              e.preventDefault();
              closeMention();
              return;
            }
            // Moving the caret horizontally leaves the token: dismiss the menu
            // but let the caret move (detectMention only re-runs on input).
            if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
              closeMention();
            }
          }
          // Enter or Tab commits a ";shortcut" sitting at the caret. Swallow the
          // key only when an expansion actually fired so normal newlines/tabs are
          // unaffected. Skipped mid-IME-composition (Enter confirms the compose).
          if (
            (e.key === "Enter" && !e.shiftKey) ||
            (e.key === "Tab" && !e.shiftKey && !e.altKey && !e.metaKey && !e.ctrlKey)
          ) {
            if (!(e.nativeEvent as KeyboardEvent).isComposing && maybeExpandSnippet(true)) {
              e.preventDefault();
            }
          }
        }}
        onInput={(e) => {
          // Never rewrite the DOM mid-IME-composition (Vietnamese input):
          // WebKit would drop or duplicate the composed text. The
          // compositionend handler below re-runs the check.
          if (!(e.nativeEvent as InputEvent).isComposing) {
            maybeExpandSnippet();
            detectMention();
          }
          emit();
        }}
        onCompositionEnd={() => {
          maybeExpandSnippet();
          detectMention();
          emit();
        }}
        onBlur={() => {
          // The menu commits on mousedown (which preempts blur), so a real blur
          // means focus left the editor - dismiss it.
          closeMention();
          emit();
          onBlur?.();
        }}
        onPaste={(e) => {
          // ⌘⇧V ("paste and match style"): keep the text, drop everything else.
          // Doing it here rather than trusting the engine keeps the behaviour
          // identical on WebKitGTK, where the combo pastes rich HTML anyway.
          const plain = e.clipboardData?.getData("text/plain") ?? "";
          if (pastePlainRef.current && plain) {
            pastePlainRef.current = false;
            e.preventDefault();
            const sel = document.getSelection();
            if (sel && sel.rangeCount) {
              replaceRangeWithText(sel.getRangeAt(0), sel, plain);
              emit();
            }
            return;
          }
          pastePlainRef.current = false;
          // Pasted images (screenshots) land inline. A refused type (SVG,
          // TIFF) doesn't consume the paste: fall through to the HTML/plain
          // branches below rather than pasting nothing at all.
          const item = [...(e.clipboardData?.items ?? [])].find((i) =>
            i.type.startsWith("image/"),
          );
          if (item) {
            const file = item.getAsFile();
            if (file && insertImageFile(file)) {
              e.preventDefault();
              return;
            }
          }
          // Clipboard HTML (web pages, Word, other mail clients) is arbitrary
          // markup: run it through the editor allowlist before it reaches the
          // DOM. Without this branch the browser would paste it unsanitized.
          const html = e.clipboardData?.getData("text/html") ?? "";
          if (html) {
            e.preventDefault();
            const clean = sanitizeEditorHtml(html);
            const sel = document.getSelection();
            if (!sel || sel.rangeCount === 0) return;
            if (clean) {
              insertFragmentAtSelection(sel, clean);
            } else if (plain) {
              // Nothing survived the allowlist; keep the plain text at least.
              replaceRangeWithText(sel.getRangeAt(0), sel, plain);
            }
            emit();
            return;
          }
          if (item && !plain) {
            // The clipboard's only payload is an image type we refuse: if we
            // let the paste through the browser inserts the raw image
            // natively, allowlist or not.
            e.preventDefault();
            return;
          }
          // A native plain-text paste is let through; the scheduled check
          // re-verifies the DOM afterwards.
          scheduleDomCheck();
        }}
        onDragStart={() => {
          internalDragRef.current = true;
        }}
        onDragEnd={() => {
          internalDragRef.current = false;
        }}
        onDrop={(e) => {
          // A drag that started inside this editor is a native "move": the
          // browser relocates the (already sanitized) selection and removes
          // the source. The next-frame check re-sanitizes regardless - it is
          // the backstop for a stale flag letting external HTML look internal.
          if (internalDragRef.current) {
            internalDragRef.current = false;
            scheduleDomCheck();
            return;
          }
          // Dragged-in HTML enters the DOM raw unless the drop is intercepted
          // just like paste is. File drops carry no text data and are left to
          // the composer's attachment handling.
          const dt = e.dataTransfer;
          if (!dt) return;
          const html = dt.getData("text/html");
          const text = dt.getData("text/plain");
          if (!html && !text) return;
          e.preventDefault();
          const el = elRef.current;
          if (!el) return;
          el.focus();
          // Put the caret where the drop landed; fall back to the end when
          // the point can't be resolved or lies outside the editor.
          let range: Range | null = null;
          if (document.caretRangeFromPoint) {
            range = document.caretRangeFromPoint(e.clientX, e.clientY);
          } else {
            const pos = document.caretPositionFromPoint?.(e.clientX, e.clientY);
            if (pos) {
              range = document.createRange();
              range.setStart(pos.offsetNode, pos.offset);
              range.collapse(true);
            }
          }
          if (!range || !el.contains(range.startContainer)) {
            range = document.createRange();
            range.selectNodeContents(el);
            range.collapse(false);
          }
          const sel = document.getSelection();
          if (!sel) return;
          sel.removeAllRanges();
          sel.addRange(range);
          if (html) {
            const clean = sanitizeEditorHtml(html);
            if (clean) insertFragmentAtSelection(sel, clean);
            else if (text) replaceRangeWithText(sel.getRangeAt(0), sel, text);
          } else {
            replaceRangeWithText(sel.getRangeAt(0), sel, text);
          }
          emit();
        }}
      />

      <input
        ref={fileRef}
        type="file"
        accept="image/*"
        multiple
        className="hidden"
        onChange={(e) => {
          for (const f of e.target.files ?? []) insertImageFile(f);
          e.target.value = "";
        }}
      />

      {/* "@" mention menu: floats at the caret (fixed, so the editor's scroll
          container can't clip it). mousedown commits before the editor blurs. */}
      {mentionOpen && mention && (
        <div
          className="co-pop-in fixed z-30 min-w-64 rounded-card border border-hairline bg-bg1 p-1 shadow-elev-2"
          style={{ left: mention.left, top: mention.top }}
          data-testid="mention-menu"
        >
          {hits.map((s, i) => (
            <button
              key={s.email}
              type="button"
              className={`flex w-full items-baseline gap-2 rounded-control px-2.5 py-1.5 text-left ${
                i === mentionCursor ? "bg-[var(--selected-bg)]" : "hover:bg-bg2"
              }`}
              onMouseDown={(e) => {
                e.preventDefault();
                insertMention(s);
              }}
              onMouseMove={() => setMentionCursor(i)}
            >
              <span className="text-base text-ink">{addressName(s)}</span>
              <span className="truncate text-xs text-ink-faint">{s.email}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
});
