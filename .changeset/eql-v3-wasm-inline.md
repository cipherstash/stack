---
'@cipherstash/stack': minor
---

`@cipherstash/stack/wasm-inline` is now EQL v3 (#614).

The WASM entry (Deno / Bun / Cloudflare Workers / Supabase Edge) previously
created a client pinned to the FFI's EQL v2 wire format, so a v3 schema
(concrete `eql_v3_*` domains) failed every encrypt on the edge. It now targets
EQL v3 exclusively:

- The factory constructs the WASM client with `eqlVersion: 3`, so v3 schemas
  encrypt/decrypt correctly on the edge.
- The entry re-exports the **v3** authoring surface (`types`, `encryptedTable`,
  the column classes, `buildEncryptConfig`, and the inference helpers) — the
  same API as `@cipherstash/stack/eql/v3` — so an Edge Function authors and runs
  v3 from one import:

  ```ts
  import { Encryption, encryptedTable, types } from "@cipherstash/stack/wasm-inline"

  const patients = encryptedTable("patients", { email: types.TextSearch("email") })
  const client = await Encryption({ schemas: [patients], config })
  ```

The v2 schema builders (`encryptedColumn` / `encryptedField` / the v2
`encryptedTable`) are no longer exported from this entry, and passing a v2 table
throws a clear error. The WASM path was never announced or documented for v2 and
had no known users; EQL v2 remains fully supported on the native
`@cipherstash/stack` entry.
