---
'@cipherstash/stack-prisma': patch
'stash': patch
---

Pin the packed `@cipherstash/eql` dependency to an exact version, closing a
route by which an installed EQL bundle could drift ahead of the code built
against it.

Both packages declared `"@cipherstash/eql": "workspace:^"` under
`dependencies`. In this workspace that resolves in-tree either way, so nothing
in development or CI could see a difference — but the two specifiers do not
pack the same. pnpm rewrites the protocol when it builds the tarball a customer
actually installs:

    "workspace:^"  packs as  "^3.0.5"
    "workspace:*"  packs as  "3.0.5"

The caret is the problem. `@cipherstash/eql` is still published from
`cipherstash/encrypt-query-language` until the publisher repoint, so a 3.0.x can
reach npm without passing through this repository at all — and `^3.0.5` accepts
it. A customer installing `stash` or `@cipherstash/stack-prisma` would then get
SQL that STORES and queries encrypted payloads at one version, while
`@cipherstash/stack`'s v3 domain types (which EMIT those payloads) and
`stack-prisma`'s baked migrations stayed frozen at the version this repo built
and tested against. The two halves of EQL are released in lockstep precisely
because that skew does not fail at install or in CI — it fails in a database.

`workspace:*` is the only form that closes it. A literal `"3.0.5"` would be an
exact pin too, but it is a registry pin: `pnpm run lint:eql-pins` rejects it,
because resolving EQL from a registry rather than from this repo is the same
drift one layer up.

No API, behaviour or SQL changes. What changes is the dependency range in the
published tarballs, and only in the narrowing direction — the version resolved
today is the version that was already being resolved. Nothing needs to be done
on upgrade.

`@cipherstash/stack` declares the same dependency under `devDependencies` and
is deliberately left alone: pnpm rewrites that range too, but no consumer of the
package ever resolves it.
