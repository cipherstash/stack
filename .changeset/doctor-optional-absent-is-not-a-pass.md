---
'stash': patch
---

`stash doctor` no longer reports "All checks passed." when `@cipherstash/stack`
is absent. The package is an optional peer, so running `doctor` before `stash
init` skips the encryption check entirely — the row already said so, but the
outro claimed a pass for a check that never ran. It now ends with "stash doctor
could not run every check.", the same line an unprobeable install gets, and
still exits 0: an absent optional package is recoverable, not a failure.
