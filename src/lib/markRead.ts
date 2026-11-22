/** Auto mark-read state machine for the open conversation (pure, DOM-free so
 *  it is unit-testable; ConversationScreen wires it to the query data, a
 *  delay timer and window visibility).
 *
 *  The rule it encodes: mark the thread read once when it opens with unread
 *  mail, then again only when genuinely new messages arrive in it. A bare
 *  rise in `unreadCount` with no new message ids is the user marking the
 *  thread unread - from then on auto mark-read stays off while the thread
 *  stays open, so the user's action is never silently undone.
 *
 *  One subtlety: a mark_read takes a beat to show up in `data` (the
 *  optimistic patch), and a refetch that was already in flight can meanwhile
 *  deliver a stale unread payload. The `dispatched` flag keeps a mark counted
 *  as in-flight until a payload shows it landed (unreadCount 0); a payload
 *  that still reports unread afterwards means the mark never landed, so the
 *  machine re-arms exactly once rather than mistaking it for a user action
 *  (and rather than retrying forever on a backend that keeps refusing).
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
  /** A mark_read was dispatched whose result hasn't shown in the data yet. */
  dispatched: boolean;
  /** A mark already failed to land once; one retry per open thread, not more. */
  retried: boolean;
}

export const emptyAutoMarkRead: AutoMarkRead = {
  threadId: null,
  knownIds: new Set<number>(),
  suppressed: false,
  pending: false,
  dispatched: false,
  retried: false,
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
      dispatched: false,
      retried: false,
    };
  }
  const hasNew = t.messageIds.some((id) => !s.knownIds.has(id));
  const knownIds = hasNew ? new Set<number>([...s.knownIds, ...ids]) : s.knownIds;

  if (t.unreadCount === 0) {
    // Caught up (our mark_read's optimistic patch, or read elsewhere): the
    // dispatch bookkeeping resets for the next arrival.
    return { ...s, knownIds, pending: false, dispatched: false, retried: false };
  }

  if (hasNew) {
    if (s.suppressed || s.dispatched) {
      // The user took over read state, or a mark is in flight that this
      // unread payload hasn't caught up with yet - if it doesn't cover the
      // new mail, the next observation re-arms.
      return { ...s, knownIds };
    }
    // Genuinely new unread messages: owed a mark.
    return { ...s, knownIds, pending: true };
  }

  if (s.pending) {
    // Unread and no new messages, but a mark is already owed: the optimistic
    // patch just hasn't landed in `data` yet - keep waiting, don't read this
    // as a user action.
    return { ...s, knownIds };
  }

  if (s.dispatched) {
    // A mark_read was dispatched but this payload still reports unread with
    // no new messages: a stale refetch landed, or the write failed and its
    // patch was overwritten. Re-arm once; if it still doesn't take, leave
    // the unread state alone.
    if (!s.retried) {
      return { ...s, knownIds, pending: true, dispatched: false, retried: true };
    }
    return { ...s, knownIds, dispatched: false };
  }

  // Unread came back with no new messages and no mark of ours in flight:
  // the user marked the thread unread.
  return { ...s, knownIds, suppressed: true, pending: false };
}

/** The mark_read was dispatched: track it as in-flight until the data shows
 *  unreadCount 0 (or a stale payload proves it never landed). */
export function markReadDispatched(s: AutoMarkRead): AutoMarkRead {
  return s.pending ? { ...s, pending: false, dispatched: true } : s;
}
