/**
 * Type tests for the wasm build's declarations (#142).
 *
 * These run against the GENERATED `dist/wasm/protect_ffi.d.ts`, so they need a
 * wasm build first. That is why they live outside `src/` and outside both root
 * tsconfigs: `npm test` must still pass in a fresh clone with no `dist/`. CI
 * runs them in the `wasm` job, immediately after `npm run build:wasm`, via
 * `npm run test:typecheck:wasm`.
 *
 * The declarations come from `typescript_custom_section` and `typescript_type`
 * in `crates/protect-ffi/src/wasm.rs` — wasm-bindgen emits them, so they cannot
 * drift from the signatures they describe. What these tests still earn is the
 * other half: that the types describe the RUST's actual contract, which no
 * compiler checks.
 *
 * The negative cases carry `@ts-expect-error`, which makes this file
 * self-verifying in both directions: if a declaration stops catching the
 * mistake below it, the suppression becomes unused and tsc fails.
 */

import {
  PROTECT_ERROR_CODES,
  decrypt,
  decryptBulk,
  decryptBulkFallible,
  encrypt,
  encryptBulk,
  encryptQuery,
  encryptQueryBulk,
  isEncrypted,
  isProtectErrorCode,
  newClient,
} from '../dist/wasm/protect_ffi.js'
import type {
  Context,
  DecryptResult,
  EncryptOptions,
  EncryptedPayload,
  JsPlaintext,
  NewClientOptions,
  ProtectErrorCode,
  QueryOpName,
  WasmClient,
} from '../dist/wasm/protect_ffi.js'

declare const client: WasmClient
declare const authStrategy: NewClientOptions['authStrategy']

// Runtime error helpers are part of the wasm surface, not type-only exports.
export const knownErrorCode: ProtectErrorCode = PROTECT_ERROR_CODES[0]
export const narrowsErrorCode: boolean = isProtectErrorCode(knownErrorCode)

// --- the shared option types are reachable from this entry at all ----------
// Before #142 none of these names existed here, and every `opts` was `any`.

const encryptOpts: EncryptOptions = {
  plaintext: 'secret',
  column: 'email',
  table: 'users',
  lockContext: { identityClaim: ['sub'] } satisfies Context,
  unverifiedContext: { requestId: 'r1' },
}
export const encrypted: Promise<EncryptedPayload> = encrypt(client, encryptOpts)

// --- lockContext placement -------------------------------------------------
// Top-level on the single calls, per payload item on the bulk ones. Getting
// this wrong is not a type curiosity: an ignored lock context yields a payload
// that looks encrypted-and-bound but is readable without the claim.

export const bulk = encryptBulk(client, {
  plaintexts: [
    {
      plaintext: 42n,
      column: 'age',
      table: 'users',
      lockContext: { identityClaim: ['sub'] },
    },
  ],
  unverifiedContext: { requestId: 'r1' },
})

export const bulkMisplaced = encryptBulk(client, {
  plaintexts: [{ plaintext: 'x', column: 'email', table: 'users' }],
  // @ts-expect-error lockContext is per payload item on the bulk path; at the
  // top level serde drops it and the values are encrypted unbound.
  lockContext: { identityClaim: ['sub'] },
})

export const queryBulk = encryptQueryBulk(client, {
  queries: [
    {
      plaintext: 'alice@example.com',
      column: 'email',
      table: 'users',
      indexType: 'unique',
      lockContext: { identityClaim: ['sub'] },
    },
  ],
})

// --- bigint plaintexts -----------------------------------------------------
// `encode_plaintext` tags these for the untagged JsPlaintext enum, so they are
// carried exactly rather than folded into an f64. Same on both bindings.

export const big: Promise<EncryptedPayload> = encrypt(client, {
  plaintext: 9223372036854775807n,
  column: 'big',
  table: 'users',
})

// --- query terms -----------------------------------------------------------

export const q = encryptQuery(client, {
  plaintext: 'alice',
  column: 'email',
  table: 'users',
  indexType: 'match',
  queryOp: 'default' satisfies QueryOpName,
})

export const badIndexType = encryptQuery(client, {
  plaintext: 'alice',
  column: 'email',
  table: 'users',
  // @ts-expect-error indexType is a closed set; a typo here previously reached
  // the Rust and failed at runtime.
  indexType: 'matsh',
})

// --- per-item decrypt results ---------------------------------------------
// The SAME `DecryptResult` the Neon entry returns, not a narrowed copy. It was
// narrowed until #146, because `code` was synthesised in the Neon JS wrapper by
// string-matching the message and so could never reach this build. Rust sets it
// now, on both bindings.

export async function readBack(): Promise<(JsPlaintext | string)[]> {
  const rows: DecryptResult[] = await decryptBulkFallible(client, {
    ciphertexts: [{ ciphertext: {} as EncryptedPayload }],
  })
  return rows.map((row) => ('data' in row ? row.data : row.error))
}

export async function codeField(): Promise<ProtectErrorCode | undefined> {
  const [row] = await decryptBulkFallible(client, { ciphertexts: [] })
  if (row && 'error' in row) {
    // Optional, not always-present: an error with no code of its own (an
    // upstream `#[error(transparent)]` wrapper) omits the field.
    return row.code
  }
  return undefined
}

// --- newClient now takes the SAME options as the Neon entry ---------------
// Both bindings deserialize one Rust `NewClientOptions`: credentials nested
// under `clientOpts`, `authStrategy` optional, keyset alongside. When no
// strategy is passed, `CredentialOpts::build_strategy()` resolves an
// `AccessKeyStrategy` from `clientOpts.accessKey` + `workspaceCrn` — the wasm
// arm of `AutoStrategy`, which is access-key-only because there is no
// filesystem to fall back to.

export const client_: Promise<WasmClient> = newClient({
  encryptConfig: { v: 1, tables: { users: { email: { cast_as: 'text' } } } },
  clientOpts: {
    clientId: '00000000-0000-0000-0000-000000000000',
    clientKey: 'deadbeef',
    workspaceCrn: 'crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY',
    accessKey: 'CSAK.test',
  },
})

export const withStrategy: Promise<WasmClient> = newClient({
  encryptConfig: { v: 1, tables: {} },
  clientOpts: {
    clientId: '00000000-0000-0000-0000-000000000000',
    clientKey: 'deadbeef',
    keyset: { Name: 'default' },
  },
  authStrategy,
  eqlVersion: 3,
})

// No strategy and no access key is legal at the type layer — the Rust reports
// it, because whether credentials resolve is a runtime question on both
// bindings.
export const bare: Promise<WasmClient> = newClient({
  encryptConfig: { v: 1, tables: {} },
})

// The deprecated alias still type-checks.
export const deprecatedName: Promise<WasmClient> = newClient({
  encryptConfig: { v: 1, tables: {} },
  strategy: authStrategy,
})

// The public `cast_as` spellings are accepted here now: normalisation moved
// into the Rust, so this binding takes the same config the Neon entry does
// rather than requiring a pre-canonicalised one.
export const publicVocabulary: Promise<WasmClient> = newClient({
  encryptConfig: { v: 1, tables: { users: { email: { cast_as: 'string' } } } },
})

export const flatCredentials = newClient({
  encryptConfig: { v: 1, tables: {} },
  // @ts-expect-error credentials live under `clientOpts` on both bindings now;
  // the flat top-level form this build used to take is gone.
  clientId: '00000000-0000-0000-0000-000000000000',
})

export const flatKeyset = newClient({
  encryptConfig: { v: 1, tables: {} },
  // @ts-expect-error `keyset` moved under `clientOpts` with the credentials.
  // This is the one the Rust cannot catch: unknown keys are dropped rather
  // than rejected (#147), so at runtime it binds to the DEFAULT keyset and
  // encrypts under the wrong keys. Here, it is a compile error.
  keyset: { Name: 'prod' },
})

// --- decrypt ---------------------------------------------------------------

export const plaintext: Promise<JsPlaintext> = decrypt(client, {
  ciphertext: {} as EncryptedPayload,
  lockContext: { identityClaim: ['sub'] } satisfies Context,
})

export const plaintexts: Promise<JsPlaintext[]> = decryptBulk(client, {
  ciphertexts: [
    {
      ciphertext: {} as EncryptedPayload,
      lockContext: { identityClaim: ['sub'] } satisfies Context,
    },
  ],
})

export const bulkLockContextPlacement = decryptBulk(client, {
  ciphertexts: [{ ciphertext: {} as EncryptedPayload }],
  // @ts-expect-error same trap as the encrypt side: `lockContext` is per item.
  // At the top level serde drops it and the values decrypt UNBOUND — the
  // identity claim the caller believes is being enforced is never checked.
  lockContext: { identityClaim: ['sub'] },
})

// --- isEncrypted -----------------------------------------------------------
// The one export declared `unknown` rather than a named type (`wasm.rs`'s
// `typescript_type` list), so it is the one place a wrong declaration would go
// unnoticed. Pin both ends: it takes anything, and it narrows nothing.

export const encryptedCheck: boolean = isEncrypted({ k: 'ct', v: 1 })
export const encryptedCheckOfGarbage: boolean = isEncrypted('not a payload')

export function isEncryptedDoesNotNarrow(value: unknown): void {
  if (isEncrypted(value)) {
    // @ts-expect-error the declaration returns `boolean`, not a type predicate.
    // Rust checks the wire shape at runtime; claiming a predicate here would
    // hand the caller a compile-time guarantee nothing backs.
    const _: EncryptedPayload = value
  }
}
