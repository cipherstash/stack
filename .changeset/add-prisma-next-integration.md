---
"@cipherstash/prisma-next": minor
"stash": minor
---

Add `@cipherstash/prisma-next` — searchable application-layer encryption for Postgres with Prisma Next. The framework's migration system installs the EQL bundle in the same `prisma-next migration apply` sweep that creates the application schema; no separate `stash db install` step.

**`@cipherstash/prisma-next` (new package, initial release)**

- **Six encrypted column types** — `EncryptedString`, `EncryptedDouble`, `EncryptedBigInt`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedJson` — declared via PSL constructors (`cipherstash.Encrypted*()`) or TS factories (`encryptedString()`, etc.).
- **17 query operators** — 13 predicate operators surfaced as column methods (`cipherstashEq`, `cipherstashIlike`, `cipherstashGt`, `cipherstashBetween`, `cipherstashInArray`, `cipherstashJsonbPathExists`, …) and 4 free-standing helpers (`cipherstashAsc`, `cipherstashDesc`, `cipherstashJsonbPathQueryFirst`, `cipherstashJsonbGet`).
- **Per-codec search-mode flags** (`equality`, `freeTextSearch`, `orderAndRange`, `searchableJson`) drive the EQL search-config indices the codec lifecycle hook emits at migration time. Defaults to `true` across the board.
- **One-call setup** via `cipherstashFromStack({ contractJson })` from `@cipherstash/prisma-next/stack` — derives the stack `encryptedTable` / `encryptedColumn` schemas from `contract.json` (single source of truth, no duplicate hand-written declarations), constructs the `@cipherstash/stack` `EncryptionClient`, builds the framework-native `CipherstashSdk` adapter, and returns ready-to-spread `{ extensions, middleware, encryptionClient }` for `postgres<Contract>({...})`.
- **Layered API** — `deriveStackSchemas(contractJson)` and `createCipherstashSdk(client, schemas)` exposed as primitives for advanced users (custom keysets, multi-tenant routing, non-stack KMS).
- **Bulk-encrypt middleware** (`bulkEncryptMiddleware(sdk)`) coalesces every plaintext placeholder across a query into one `bulkEncrypt` SDK round-trip per `(table, column)` group. `decryptAll(rows)` does the symmetric coalescing on the read side.
- **Misconfig diagnostic** — if the user constructs the runtime descriptor but forgets to register `bulkEncryptMiddleware(sdk)` against the same SDK, the codec's encode throws a `RUNTIME.ENCODE_FAILED` envelope with a copy-pasteable wiring snippet at the first encrypted write.
- **Subpath exports** — `./stack`, `./control`, `./runtime`, `./middleware`, `./pack`, `./column-types`; tree-shakable along the control / runtime / middleware seams.
- **Contributes an EQL contract space** — installs the `eql_v2` schema, `eql_v2_encrypted` composite type, `ore_*` types, EQL functions / operators / casts via the cipherstash extension's baseline migration. Runs in the same control-plane sweep as the application schema.
- **Full docs**: https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next.

**`stash` (new feature)**

- **`stash init --prisma-next`** — new init provider for Prisma Next projects. Reuses `authenticate` + `resolve-database` + `install-deps` (additionally installs `@cipherstash/prisma-next`), skips `install-eql` (the framework handles it via `prisma-next migration apply`) and `build-schema` (`cipherstashFromStack` derives schemas from the contract — no hand-written encryption client file). Detected automatically when a `prisma-next.config.*` or `@cipherstash/prisma-next` dependency is present in the project.
- **`detectPrismaNext(cwd)`** — new export from `commands/db/detect.ts` mirroring the existing `detectDrizzle` / `detectSupabase` helpers.
