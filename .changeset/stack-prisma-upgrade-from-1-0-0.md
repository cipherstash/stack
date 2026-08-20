---
'@cipherstash/stack-prisma': patch
---

Document the 1.0.0 → 3.0.5 upgrade in the package README: why
`migrations/cipherstash/` must be deleted and regenerated, what each Prisma Next
command does if it is not, and the exact `db init` refusal
(`Operation cipherstash.upgrade-eql-v3-bundle-3.0.5 has class "data" which is
not allowed by policy.`) that a stale vendored directory produces on a fresh
database.

The behaviour worth knowing regardless of version: only `prisma-next migration
plan` copies new migration packages into your repo. Running `migrate` or
`db init` after upgrading this package without planning first silently leaves
the database on the older EQL bundle — a stale vendored directory is internally
intact, so it passes every integrity check and nothing reports a problem.
