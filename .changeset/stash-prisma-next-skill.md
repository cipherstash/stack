---
'stash': minor
---

`stash init`, `stash plan`, and `stash impl` no longer crash on a Prisma Next
project. `SKILL_MAP` was missing a `prisma-next` entry, so the skills-install
and AGENTS.md-builder steps hit `SKILL_MAP[integration]` → `undefined` and threw
"not iterable" for any repo the CLI detected as Prisma Next. The entry is added
and both consumers now resolve skills through a `skillsFor()` helper that
degrades an unmapped integration to the base skill set instead of crashing
(`tsup` ships without type-checking, so the `Record<Integration>` type alone
didn't protect the build).

Ships a new **`stash-prisma-next`** agent skill documenting the EQL v3 Prisma
Next surface — the domain-named encrypted column types (`EncryptedTextSearch`,
`EncryptedDoubleOrd`, …), `cipherstashFromStackV3` wiring, the runtime value
envelopes, the `eql*` query operators, and EQL installation via
`prisma-next migration apply`. It is installed for Prisma Next projects and
inlined into `AGENTS.md` for editor agents.

`stash eql install` now refuses to run in a Prisma Next project (pointing you
at `prisma-next migration apply`, which owns EQL installation) unless you pass
`--force` — closing the manual-invocation hole that `stash init --prisma-next`
already avoided.
