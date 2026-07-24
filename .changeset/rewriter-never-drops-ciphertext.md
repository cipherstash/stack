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
`"o'brien_data"` no longer opens a phantom string literal, and a doubled `''` or
`""` reads as an escape rather than a delimiter.

The sweep also refuses to rewrite a column the migration corpus already gives an
encrypted type, so changing a column's encrypted domain no longer drops a column
full of ciphertext. Skipped statements report why they were left alone.

An unreadable migration directory (`EACCES`) is reported rather than silently
treated as empty, and the wizard's `Run the migration now?` prompt defaults to No
whenever the sweep rewrote anything, flagged anything, or could not check a
directory at all — naming the directories that went unchecked, and making no
claim about data destruction for a directory nothing is known about.
