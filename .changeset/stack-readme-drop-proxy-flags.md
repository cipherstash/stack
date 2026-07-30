---
'@cipherstash/stack': patch
---

README only — drop the removed `--proxy` / `--no-proxy` flags from the `stash init`
flag table.

The flags went away with the EQL v2 CipherStash Proxy lifecycle: they are absent
from the CLI command registry, and `stash init` now rejects them with an
actionable message. `packages/cli/README.md` and the bundled `stash-cli` skill
were already updated, but this table row in the `@cipherstash/stack` README —
which ships in the tarball — still documented them as supported.
