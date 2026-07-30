---
'stash': minor
---

`stash init` now takes `--prisma`, the Prisma Next setup flag, replacing
`--prisma-next`. This makes the integration flags consistent — `--supabase`,
`--drizzle`, `--prisma` — and matches how `--supabase` is used for referrer
tracking. `--prisma` selects the same Prisma Next flow (EQL bundle installed via
`prisma-next migrate`, no encryption-client scaffold) and records `prisma` as the
referrer.

**Breaking:** `stash init --prisma-next` is no longer recognized. Init errors with
guidance to re-run with `--prisma`. The bundled `stash-cli` skill is updated to
document the new flag.
