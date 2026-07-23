---
'@cipherstash/migrate': patch
---

Drop EQL v2 from the domain-type classifier. `classifyEqlDomain` (and the
`detectColumnEqlVersion` / `listEncryptedColumns` / `resolveEncryptedColumn`
resolution built on it) no longer recognise the legacy `eql_v2_encrypted`
domain — v3 is the sole generation this workspace authors and backfills, so a
column's version is now determined solely from its self-describing `eql_v3_*`
domain type. A legacy v2 column's version is carried by the manifest's recorded
`eqlVersion` instead (the CLI's `encrypt status` / `status` renderers already
fall back to it), so status output is unchanged for v2 columns already recorded
in `.cipherstash/migrations.json`. A v2 column backfilled from here on records
no `eqlVersion` and so reports no version in `stash encrypt status` — the v2
lifecycle itself (cut-over, then dropping `<column>_plaintext`) is unaffected.

This removes v2 *classification*, not the v2 read path: existing v2 ciphertext
remains decryptable through `@cipherstash/stack`. `EqlVersion` keeps its `2`
member for manifest-sourced legacy values; the exported function signatures are
unchanged.
