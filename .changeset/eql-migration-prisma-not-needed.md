---
'stash': patch
---

`stash eql migration --prisma`: say "not needed", not "not yet".

The command's registry copy, error message, and the `stash-cli` skill all
described a Prisma Next emitter as a coming follow-up. Prisma Next doesn't
need one — its extension pack installs the EQL bundle through prisma-next's
own migration framework (the `migrations/cipherstash/` contract space). The
`--prisma` flag now exists purely to route people there: the error explains
the mechanism and points at `prisma-next migration plan` / `prisma-next
migrate`.
