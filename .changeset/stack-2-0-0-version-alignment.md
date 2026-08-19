---
'stash': major
'@cipherstash/stack': major
'@cipherstash/stack-drizzle': major
'@cipherstash/stack-supabase': major
'@cipherstash/wizard': major
---

**No breaking changes in this package.** Upgrading from 1.x to 2.0.0 needs no
code changes, and there is no migration guide to look for.

The major version comes from `@cipherstash/stack-prisma`, which does have a
breaking change this release — it moves to Prisma Next 0.17, and its own
changelog carries the upgrade steps. These six packages share a single version
line, so a major in any one of them takes all six to the same number:

- `stash`
- `@cipherstash/stack`
- `@cipherstash/stack-drizzle`
- `@cipherstash/stack-supabase`
- `@cipherstash/stack-prisma`
- `@cipherstash/wizard`

They are versioned together on purpose. `stash init` pins the versions of the
packages it installs, and the CLI embeds that map at build time — so if one
package could ship without the others, the CLI would start recommending
versions that no longer match what is published, and warn about a skew it had
itself created.

**If you do not use `@cipherstash/stack-prisma`, this release is additive.**
Read your package's own Minor and Patch entries below for what actually changed
in it.
