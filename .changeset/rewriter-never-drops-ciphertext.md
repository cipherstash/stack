---
'@cipherstash/wizard': patch
'stash': patch
---

Fix a data-loss bug in the Drizzle migration rewriter: a **commented-out**
`ALTER … SET DATA TYPE` was rewritten into executable SQL. The matcher was
comment-blind and the replacement is multi-line, so the author's `-- ` survived
on the first line only — the `DROP COLUMN` on the next line emitted live and
dropped a populated column.

A statement is now left exactly as written whenever it is inert — inside a `--`
line comment, inside a `/* … */` block, or inside a single-quoted string
literal, where an `ALTER` is data rather than SQL. (Rewriting one splices
`--> statement-breakpoint` markers *inside* the literal, so splitting the file
the way drizzle's migrator does yields a bare, live `DROP COLUMN` as a chunk of
its own.) Quoting is tokenised properly in the process: a `--` inside a string
no longer opens a comment, an apostrophe inside a quoted identifier such as
`"o'brien_data"` no longer opens a phantom string literal, a doubled `''` or
`""` reads as an escape rather than a delimiter, and an unterminated quote of
either kind makes the rest of the file inert rather than live.

The sweep also refuses to rewrite a column the migration corpus already gives an
encrypted type, so changing a column's encrypted domain no longer drops a column
full of ciphertext. Skipped statements report why they were left alone.

The sweep is now fail-closed about the columns it does not recognise at all.
Previously a column missing from the corpus index was assumed to be plaintext
and rewritten; absence is not evidence, and the declaration can simply live in a
migration directory the sweep never reads — the wizard ships scanning three of
them and indexes each separately. Such a statement is now reported for review
rather than rewritten, so the ADD+DROP+RENAME can no longer drop a column that
already holds ciphertext. If your migration history is squashed, or the column's
`CREATE TABLE` lives outside the directory being swept, you will see the
statement flagged instead of repaired: check the column's current type and
either apply the rewrite by hand on an empty table, or use the staged
`stash encrypt` lifecycle.

An unreadable migration directory (`EACCES`) is reported rather than silently
treated as empty, and the wizard's `Run the migration now?` prompt defaults to No
whenever the sweep rewrote anything, flagged anything, or could not check a
directory at all — naming the directories that went unchecked, and making no
claim about data destruction for a directory nothing is known about.
