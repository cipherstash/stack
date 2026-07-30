---
'@cipherstash/stack-prisma': minor
'@cipherstash/wizard': patch
'stash': minor
---

Renamed `@cipherstash/prisma-next` to **`@cipherstash/stack-prisma`** (#842),
matching the `@cipherstash/stack-drizzle` / `@cipherstash/stack-supabase`
adapter naming. Only the npm name changes: the `prisma-next` CLI,
`prisma-next.config.ts`, and the `@prisma-next/*` framework packages are the
Prisma Next framework's own surface and keep their names. Update imports
(`@cipherstash/prisma-next/stack` → `@cipherstash/stack-prisma/stack`, and the
other subpaths likewise) and the `extensionPacks` import in
`prisma-next.config.ts`.

`stash init` and the bundled skills now install and document the new name; the
`stash-prisma-next` skill is now `stash-prisma`.
