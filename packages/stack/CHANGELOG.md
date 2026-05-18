# @cipherstash/stack

## 0.16.0

### Minor Changes

- 1c2fdbf: Fix CJS consumers crashing with `Must use import to load ES Module: .../uuid/dist-node/index.js`. The `uuid` package is pure ESM and has no CJS entry point, so the CJS build of `@cipherstash/stack` could not `require()` it at runtime. `uuid` is now bundled into the CJS output (the ESM build is unchanged).

  Expose `EncryptedTable.columnBuilders` as a public, read-only field so consumers can iterate the typed column-builder map of an encrypted table without reaching into the built `TableDefinition` (`schema.build().columns`) or the private internal.

## 0.15.3

### Patch Changes

- afe6810: Bump protect-ffi version

## 0.15.2

### Patch Changes

- 510c485: Bundle `evlog` into the CJS output. `evlog` is pure ESM (no `require` condition in its `exports` map), so CJS consumers of `@cipherstash/stack` (e.g. webpack bundles) were failing with `ERR_PACKAGE_PATH_NOT_EXPORTED` when the stack's `index.cjs` tried to `require("evlog")`. `evlog` is now inlined at build time and no longer resolved at runtime.

## 0.15.1

### Patch Changes

- 8513705: Fix mangled `eql_v2_encrypted` type in drizzle-kit migrations.

  - `@cipherstash/stack/drizzle`'s `encryptedType` now returns the bare `eql_v2_encrypted` identifier from its Drizzle `customType.dataType()` callback. Returning the schema-qualified `"public"."eql_v2_encrypted"` (0.15.0) triggered a drizzle-kit quirk that wraps the return value in double-quotes and prepends `"{typeSchema}".` in ALTER COLUMN output — producing `"undefined".""public"."eql_v2_encrypted""`, which Postgres cannot parse.
  - `stash db install` / `stash wizard`'s migration rewriter now matches all four forms drizzle-kit may emit (`eql_v2_encrypted`, `"public"."eql_v2_encrypted"`, `"undefined"."eql_v2_encrypted"`, `"undefined".""public"."eql_v2_encrypted""`) and rewrites each into the safe `ADD COLUMN … DROP COLUMN … RENAME COLUMN` sequence.

  Users on 0.15.0 who hit this in generated migrations should upgrade and re-run `npx drizzle-kit generate` + `stash db install` (or re-run the wizard).

## 0.15.0

### Minor Changes

- 1929c8f: Mark secrets as a coming soon feature and remove existing SDK integration.

## 0.14.0

### Minor Changes

- 1e0d4c1: Support CipherStash rebrand with new docs links.

## 0.13.0

### Minor Changes

- 068f820: Release the consolidated CipherStash CLI npm package.

## 0.12.0

### Minor Changes

- 15764a8: Implement stack auth into stash cli flow.

## 0.11.0

### Minor Changes

- b0e56b8: Upgrade protect-ffi to 0.21.0 and enable array_index_mode for searchable JSON

  - Upgrade `@cipherstash/protect-ffi` to 0.21.0 across all packages
  - Enable `array_index_mode: 'all'` on STE vec indexes so JSON array operations
    (jsonb_array_elements, jsonb_array_length, array containment) work correctly
  - Delegate credential resolution entirely to protect-ffi's `withEnvCredentials`
  - Download latest EQL at build/runtime instead of bundling hardcoded SQL files

## 0.10.0

### Minor Changes

- 5245cd7: Improved CLI setup and initialization commands.

## 0.9.0

### Minor Changes

- 2b907a1: Improve CLI user experience for developer onboarding.

## 0.8.0

### Minor Changes

- 3414761: Fixed Supabase or wrapper to escape EQL payloads correctly.

## 0.7.0

### Minor Changes

- 1be8f81: Exposed a public method on the Encryption client to expose the build Encryption schema.

## 0.6.0

### Minor Changes

- 0b9fd7a: Add notes to CLI about init in prototype phase.

## 0.5.0

### Minor Changes

- a645115: ### Documentation

  - **TypeDoc**: Improved JSDoc for `Encryption()`, `EncryptOptions`, schema builders (`encryptedTable`, `encryptedColumn`, `encryptedField`, `EncryptedField`, `EncryptedTableColumn`), and `encrypt` / `bulkEncrypt` with clearer `@param`, `@returns`, `@throws`, `@example`, and `@see` links.
  - **README**: Refreshed main repo README and Stack package readme; basic example README now uses `npm install @cipherstash/stack`, CipherStash account and dashboard credentials, and drops Stash CLI references. Added docs badge linking to cipherstash.com/docs.

  ### Features

  - **Logging**: Logger is now used consistently across Stack client interfaces for initialization and operations.

## 0.4.0

### Minor Changes

- 5c3f4e7: Remove null support from encrypt and bulk encrypt operations to improve typescript support and reduce operation complexity.

## 0.3.0

### Minor Changes

- afe0a55: Improved encrypt model return types to account for Encrypted values.

## 0.2.0

### Minor Changes

- 68c8199: Improved typing for model interfaces and full bun support.

## 0.1.0

### Minor Changes

- 7ed89a5: Initial release of the CipherStash Stack.
