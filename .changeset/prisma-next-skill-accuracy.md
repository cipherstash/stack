---
'stash': patch
---

Correct the `stash-prisma` skill against the current adapter, and fix a
stale constructor name in `stash init --prisma-next`'s next steps.

The skill was verified line-by-line against `@cipherstash/stack-prisma` on
main (constructors, domains, operators, `rawSql` shape, EQL function names,
CLI commands — all confirmed current). Two real errors fixed:

- The config example imported `defineConfig` from `'prisma-next'` — no such
  package exists; it comes from `@prisma-next/cli/config-types`.
- The bundling section suggested `@cipherstash/stack/wasm-inline` for edge
  runtimes — the Prisma Next adapter is native-only (`cipherstashFromStack`
  constructs the native stack client; there is no WASM variant), so the
  advice was a dead end. It now says so.

The column-type section now carries the **complete 31-constructor catalog**
(plaintext TS type × capability tier) instead of a six-row sample presented
as the whole surface (#756): every family (`Text*`, `Integer*`, `Smallint*`,
`BigInt*`, `Numeric*`, `Real*`, `Double*`, `Date*`, `Timestamp*`, `Boolean`,
`Json`) with its plaintext type — the column that distinguishes
`IntegerOrd` (JS `number`) from `BigIntOrd` (JS `bigint`) and would have
prevented the integer-cents trap the issue reports. Also states that `*Ord`
includes equality, `TextMatch` is free-text only, and the `*OrdOre` variants
are deliberately unexposed.

Also documented the `column-types` subpath (camelCase factories for
TS-authored contracts), and fixed `stash init --prisma-next`'s next-steps
message, which still told users to declare columns with the old
`cipherstash.Encrypted*()` constructor names (current: `cipherstash.TextSearch()`,
`cipherstash.DateOrd()`, …).
