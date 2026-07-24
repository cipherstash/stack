---
'@cipherstash/wizard': patch
'stash': patch
---

Fix a data-loss bug in the Drizzle migration rewriter: a **commented-out**
`ALTER … SET DATA TYPE` was rewritten into executable SQL. The matcher was
comment-blind and the replacement is multi-line, so the author's `-- ` survived
on the first line only — the `DROP COLUMN` on the next line emitted live and
dropped a populated column. Statements inside a `--` line comment or a `/* … */`
block are now left as written, and a `--` inside a string literal no longer
reads as a comment.

The sweep also refuses to rewrite a column the migration corpus already gives an
encrypted type, so changing a column's encrypted domain no longer drops a column
full of ciphertext. Skipped statements report why they were left alone.

An unreadable migration directory (`EACCES`) is reported rather than silently
treated as empty, and the wizard's `Run the migration now?` prompt defaults to No
whenever the sweep rewrote anything, flagged anything, or could not check a
directory at all — naming the directories that went unchecked, and making no
claim about data destruction for a directory nothing is known about.
