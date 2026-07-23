---
'@cipherstash/wizard': minor
---

Teach the wizard's post-agent Drizzle step to repair EQL **v3** migrations, not
just legacy EQL v2.

The wizard now scaffolds EQL v3 columns, so `drizzle-kit generate` emits
`ALTER TABLE … ALTER COLUMN … SET DATA TYPE eql_v3_<name>` — which Postgres
rejects (there is no cast from `text`/`numeric` to an EQL domain). The migration
rewriter previously matched only the single `eql_v2_encrypted` type, so those v3
statements slipped through unrepaired and failed at migrate time.

The rewriter is ported to match the whole EQL v3 concrete-domain family
(`eql_v3_text_search`, `eql_v3_integer_ord`, …) alongside legacy
`eql_v2_encrypted`, across every mangled form drizzle-kit emits (including the
`"undefined".` prefix from 0.31.0+ and schema-qualified `pgSchema()` tables). It
now also flags near-miss `SET DATA TYPE … USING …` statements it cannot safely
repair instead of leaving broken SQL, and each rewritten file carries a clearer
warning that the ADD+DROP+RENAME is data-destroying and safe only on an empty
table — a populated table must use the staged `stash encrypt` flow. This
re-converges the rewriter with the sibling copy in the `stash` CLI.

The post-agent step now sweeps **every** candidate migration directory
(`drizzle/`, `migrations/`, `src/db/migrations/`) rather than stopping at the
first one that exists. Previously an empty or already-rewritten `drizzle/`
sitting next to a project's real `migrations/` caused those migrations to be
skipped entirely, so they still failed at migrate time. A directory that can't
be read is reported and the remaining candidates are still swept. Reported
near-miss statements are also trimmed of any preceding comment block, so the
statement quoted back to the user is the offending statement alone.

Database introspection also recognises v3 encrypted columns: `isEqlEncrypted`
now reports both `eql_v2_encrypted` and the `eql_v3_*` family as already
encrypted, so the agent won't scaffold over existing encrypted data of either
generation.
