---
'stash': patch
---

`stash init` now scaffolds an EQL **v3** encryption client, matching the EQL v3
database it installs.

The placeholder client (`DRIZZLE_PLACEHOLDER` / `GENERIC_PLACEHOLDER`) and the
introspection-driven client generator previously emitted legacy EQL v2
authoring patterns. Since init installs a v3 database, this handed the
customer's coding agent v2 guidance against a v3 schema (follow-up to #732 /
#705).

Scaffolds now teach the v3 surface: `Encryption` from `@cipherstash/stack/v3`,
the concrete-domain `types.*` factories (`types.TextSearch`, `types.IntegerOrd`,
`types.Text`, `types.Json`, …), and the `@cipherstash/stack-drizzle/v3` entry
(`extractEncryptionSchemaV3`) for Drizzle. The `encryptionClient` export shape
and the empty-schema "no schemas yet" error path are unchanged.

The scaffolds emit `extractEncryptionSchema` from the collapsed
`@cipherstash/stack-drizzle` root.
