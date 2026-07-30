---
'@cipherstash/stack': minor
---

`@cipherstash/stack/wasm-inline` is now EQL v3 (#614).

The WASM entry (Deno / Bun / Cloudflare Workers / Supabase Edge) previously
created a client pinned to the FFI's EQL v2 wire format, so a v3 schema
(concrete `eql_v3_*` domains) failed every encrypt on the edge. It now targets
EQL v3 exclusively:

- The factory builds an EQL v3 WASM client, so v3 schemas
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

Only the EQL v3 schema authoring surface is public, and passing a legacy table
shape throws a clear error. The WASM path was never announced or documented for
v2 and had no known users. The native `@cipherstash/stack` entry continues to
decrypt stored EQL v2 payloads, but new clients author EQL v3 only.
