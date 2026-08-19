---
'stash': patch
---

`skills/stash-prisma` now documents the re-plan step that follows an
`@cipherstash/stack-prisma` upgrade: `rm -rf migrations/cipherstash && npx
prisma-next migration plan`, why only `migration plan` vendors new migration
packages, and the exact `db init` refusal a stale vendored directory produces on
a fresh database (`Operation cipherstash.upgrade-eql-v3-bundle-3.0.5 has class
"data" which is not allowed by policy.`).

The package README already carried this; the skill did not — and the skill is
what ships inside the `stash` tarball and gets copied into a user's
`.claude/skills/`, so an agent driving the upgrade hit the refusal with no route
out of it. `packages/stack-prisma/test/v3/stale-vendored-space.test.ts` now pins
both files to the planner's real message so they cannot drift apart again.
