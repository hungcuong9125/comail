-- Durable marker for account removal in flight. remove_account inserts the
-- account id before the first destructive step (the batched FTS sweep), so a
-- crash, a failed batch, or a rolled-back final transaction never leaves the
-- account's search index silently half-destroyed: on restore the account is
-- re-indexed and the marker cleared; on the next start-up the marker resumes
-- the removal the user asked for. Cleared inside the delete transaction.
CREATE TABLE removing_accounts (
  account_id INTEGER PRIMARY KEY,
  marked_at INTEGER NOT NULL
);
