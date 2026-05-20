---
"@cipherstash/protect": minor
"@cipherstash/stack": minor
"@cipherstash/schema": minor
"@cipherstash/protect-dynamodb": patch
"@cipherstash/prisma-next": minor
"stash": minor
---

Upgrade `@cipherstash/protect-ffi` to `0.22.0` and the bundled CipherStash EQL extension to `eql-2.3.0`.

Breaking upstream changes adopted in this release:

- **Encrypt-config schema version**: `buildEncryptConfig` now emits `{ v: 1, ... }` (was `{ v: 2, ... }`). protect-ffi `0.22.0` validates this field and rejects any value other than `1` with the new `UNSUPPORTED_CONFIG_VERSION` error code.
- **SteVec encoding default flipped**: protect-ffi's default `mode` for `ste_vec` indexes changed from `compat` to `standard`. The two encodings are not cross-compatible. Existing JSON-searchable data that was indexed under `compat` will need to be re-encrypted to be queryable. The stack adopts the new `standard` default — there is no longer a way to pin `compat` from the SDK.
- **EQL extension bumped to `eql-2.3.0`**: the new SteVec `standard` encoding requires matching support in the database EQL extension. The CLI's bundled SQL (`packages/cli/src/sql/*.sql`) and the `@cipherstash/prisma-next` install bundle (`migrations/20260601T0000_install_eql_bundle/ops.json` + `eql-install.generated.ts`) are updated to `eql-2.3.0`. Databases installed with an older EQL extension must be reinstalled (`stash db install`) before containment / contained-by queries against SteVec columns will work.
- **New error codes**: `ProtectErrorCode` (re-exported from `@cipherstash/protect-ffi`) gains `MATCH_REQUIRES_TEXT` and `UNSUPPORTED_CONFIG_VERSION`. Exhaustive switches over `ProtectErrorCode` will need additional cases.
- **`match` index validation**: protect-ffi now rejects `match` indexes on columns whose `cast_as` is not text-family (`'text'` / `'string'`) with `MATCH_REQUIRES_TEXT`. The stack's `freeTextSearch()` builder is unaffected because it only targets string-typed columns.
- **`Encrypted` ciphertext shape**: protect-ffi's `Encrypted` type is now a discriminated union keyed on `k` (`'ct'` for scalars, `'sv'` for SteVec). SteVec storage payloads now place the root document ciphertext at `sv[0].c`. The stack's `isEncryptedPayload` runtime check continues to work because storage payloads still carry `c` (scalar) or `sv` (SteVec). The DynamoDB helpers (`toEncryptedDynamoItem`, `SearchTermsOperation`) now narrow on `k` before reading variant-only fields.
- **Config-validation error message wording**: error messages for config-validation failures now come from upstream `ConfigError`. `ProtectError.code` values are preserved; consumers that string-match on `err.message` for config-validation errors must update.
