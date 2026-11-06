---
'stash': patch
---

`stash keyset rewrap` now refuses to move a `wrapped`-mode record to another
vendor key, with the code `rewrap_refused`, before any vendor call. Each stored
value keeps its data key wrapped under the vendor key that sealed it, so such a
move would leave the stored values unable to open. A `wrapped` record may still
move to a new version of its own key (after a rotation), and a `derived` record
may move to any key. The command help, the note it prints, the README and the
`stash-cli` skill state the rule. The `stash-zerokms` skill now says that key
vendor backends exist for the Rust crates and the Go SDK, that TypeScript does
not support them yet, and that `stash keyset` creates their keyset records.
