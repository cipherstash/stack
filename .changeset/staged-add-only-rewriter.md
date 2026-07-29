---
'stash': patch
'@cipherstash/wizard': patch
---

The Drizzle migration rewriter now preserves the source column and adds a staged
encrypted twin instead of emitting destructive drop/rename SQL. When the sweep
cannot prove a source column's type or the encrypted twin already exists, the
CLI and wizard fail closed with a non-zero exit so the migration directory must
be reviewed before applying it.
