---
"stash": minor
"@cipherstash/wizard": minor
---

Rename `stash db install`, `stash db upgrade`, and `stash db status` to
`stash eql install`, `stash eql upgrade`, and `stash eql status`. These
commands manage the EQL extension itself, so they now live under a dedicated
`eql` command group. The old `db` spellings keep working as deprecated
aliases that print a warning pointing at the new names. All help text,
hints, generated migration headers, and wizard steps now reference the
`eql` commands.
