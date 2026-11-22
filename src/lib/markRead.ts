/** Auto mark-read state machine for the open conversation (pure, DOM-free so
 *  it is unit-testable; ConversationScreen wires it to the query data, a
 *  delay timer and window visibility).
 *
 *  The rule it encodes: mark the thread read once when it opens with unread
 *  mail, then again only when genuinely new messages arrive in it. A bare
 *  change in `unreadCount` with no new message ids is the user marking the
 *  thread unread (the optimistic patch bumps the count but adds no message) -
 *  from then on auto mark-read stays off while the thread stays open, so the
 *  user's action is never silently undone.
 */

export interface ThreadSnapshot {
  threadId: number;
  unreadCount: number;
  /** Ids of the non-draft messages currently in the detail payload. */
  messageIds: readonly number[];
}

export interface AutoMarkRead {
  /** The thread this session tracks, or null before the first snapshot. */
  threadId: number | null;
  /** Message ids seen so far in the open thread. */
  knownIds: ReadonlySet<number>;
  /** The user marked the open thread unread: no more auto marks this session. */
  suppressed: boolean;
  /** Unread mail is waiting to be marked (delay running / window hidden). */
  pending: boolean;
}

export const emptyAutoMarkRead: AutoMarkRead = {
  threadId: null,
  knownIds: new Set<number>(),
  suppressed: false,
  pending: false,
};

/** Fold a fresh detail payload into the session. `pending` in the result
 *  means a mark_read is owed once the window is visible and focused. */
export function observeThread(s: AutoMarkRead, t: ThreadSnapshot): AutoMarkRead {
  const ids = new Set(t.messageIds);
  if (s.threadId !== t.threadId) {
    // A different thread opened: its unread state is shown to the user.
    return {
      threadId: t.threadId,
      knownIds: ids,
      suppressed: false,
      pending: t.unreadCount > 0,
    };
  }
  const hasNew = t.messageIds.some((id) => !s.knownIds.has(id));
  const knownIds = hasNew ? new Set<number>([...s.knownIds, ...ids]) : s.knownIds;
  if (hasNew) {
    // Genuinely new messages: owed a mark unless the user took over read
    // state by marking the thread unread themselves.
    return { ...s, knownIds, pending: !s.suppressed && t.unreadCount > 0 };
  }
  if (t.unreadCount === 0) {
    // Caught up (our mark_read's optimistic patch, or read elsewhere).
    return { ...s, knownIds, pending: false };
  }
  if (s.pending) {
    // Unread and no new messages, but a mark is already owed: the optimistic
    // patch just hasn't landed in `data` yet - keep waiting, don't read this
    // as a user action.
    return { ...s, knownIds };
  }
  // Unread came back with no new messages: the user marked the thread unread.
  return { ...s, knownIds, suppressed: true, pending: false };
}

/** The mark_read was dispatched: the payload will show unread until the
 *  optimistic update lands, so stop counting it as owed. */
export function markReadDispatched(s: AutoMarkRead): AutoMarkRead {
  return s.pending ? { ...s, pending: false } : s;
}
