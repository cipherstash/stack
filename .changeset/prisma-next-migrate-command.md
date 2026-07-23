---
'stash': patch
'@cipherstash/prisma-next': patch
---

Fix the wrong `prisma-next migration apply` command name in the Prisma Next
guidance. Prisma Next has no `migration apply` subcommand — the apply verb is the
top-level `prisma-next migrate` (`migration` only has `plan`/`new`/`show`/
`status`/`log`/`list`/`graph`/`check`). The stale name appeared in the
`stash-prisma-next` and `stash-cli` skills, the `@cipherstash/prisma-next`
README, and — user-visibly — in `stash init --prisma-next`'s printed next-steps,
the `stash init` flag help, and the `stash eql install` Prisma-Next refusal
message, all of which now say `prisma-next migrate`. Surfaced by the rc.4
skilltester run (found independently at Prisma Next 0.14.0, confirmed at 0.16.0).
