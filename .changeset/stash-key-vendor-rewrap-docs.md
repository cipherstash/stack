---
'stash': patch
---

Correct what `stash keyset rewrap` says about stored values. A rewrap does not
re-key stored data. In the `derived` mode stored values stay readable. In the
`wrapped` mode each value's data key stays wrapped under the vendor key that
sealed it, so a rewrap to a new version of the same key keeps them readable,
but a rewrap to another `--vendor-key` makes the values sealed before it fail
to open. The command help, the note it prints, and the `stash-cli` skill now
say so, and the README has a `stash keyset` section. The `stash-zerokms` skill now says that key vendor backends exist for
the Rust crates and the Go SDK, that TypeScript does not support them yet, and
that `stash keyset` creates their keyset records.
