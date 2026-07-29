---
'stash': patch
---

Correct the `stash-prisma-next` skill against the current adapter, and fix a
stale constructor name in `stash init --prisma-next`'s next steps.

The skill was verified line-by-line against `@cipherstash/prisma-next` on
main (constructors, domains, operators, `rawSql` shape, EQL function names,
CLI commands — all confirmed current). Two real errors fixed:

- The config example imported `defineConfig` from `'prisma-next'` — no such
  package exists; it comes from `@prisma-next/cli/config-types`.
- The bundling section suggested `@cipherstash/stack/wasm-inline` for edge
  runtimes — the Prisma Next adapter is native-only (`cipherstashFromStack`
  constructs the native stack client; there is no WASM variant), so the
  advice was a dead end. It now says so.

Also documented the `column-types` subpath (camelCase factories for
TS-authored contracts), and fixed `stash init --prisma-next`'s next-steps
message, which still told users to declare columns with the old
`cipherstash.Encrypted*()` constructor names (current: `cipherstash.TextSearch()`,
`cipherstash.DateOrd()`, …).
