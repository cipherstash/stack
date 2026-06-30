/**
 * WASM-inline entry for `@cipherstash/stack` — for Deno, Bun, Cloudflare
 * Workers, Supabase Edge Functions, and any runtime where the native
 * `@cipherstash/protect-ffi` NAPI bindings are unavailable.
 *
 * Mirrors the protect-ffi / auth `/wasm-inline` pattern: the WASM module
 * is inlined into the JS bundle as a base64 blob (no separate `.wasm`
 * fetch / file read), so this entry works in environments that disallow
 * `fs` or relative asset loading.
 *
 * Use this import path: `@cipherstash/stack/wasm-inline`
 *
 * @example
 * ```ts
 * import {
 *   Encryption, encryptedTable, encryptedColumn,
 * } from "@cipherstash/stack/wasm-inline"
 *
 * const users = encryptedTable("users", { email: encryptedColumn("email") })
 *
 * const client = await Encryption({
 *   schemas: [users],
 *   config: {
 *     workspaceCrn: Deno.env.get("CS_WORKSPACE_CRN")!,
 *     accessKey:    Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
 *     clientId:     Deno.env.get("CS_CLIENT_ID")!,
 *     clientKey:    Deno.env.get("CS_CLIENT_KEY")!,
 *   },
 * })
 *
 * const enc = await client.encrypt("alice@example.com", {
 *   column: users.email,
 *   table: users,
 * })
 * const dec = await client.decrypt(enc)
 * ```
 *
 * For per-user, identity-bound encryption on the edge, build an
 * `OidcFederationStrategy` (federates an end user's OIDC JWT — Clerk,
 * Supabase, … — into a CTS service token) and pass it via
 * `config.strategy`:
 *
 * ```ts
 * import { OidcFederationStrategy } from "@cipherstash/stack/wasm-inline"
 * import { cookieStore } from "@cipherstash/auth/cookies"
 *
 * const strategy = OidcFederationStrategy.create(
 *   "crn:ap-southeast-2.aws:my-workspace-id", () => getClerkSessionToken(req),
 *   { store: cookieStore({ request: req, responseHeaders }) },
 * )
 * const client = await Encryption({ schemas, config: { strategy, clientId, clientKey } })
 * ```
 *
 * For service-to-service / CI use with a custom token store, build an
 * `AccessKeyStrategy.create(workspaceCrn, accessKey, { store })` the same
 * way (it derives the region from the CRN). Both strategies are
 * re-exported from this entry.
 */

import {
  AccessKeyStrategy,
  type OidcFederationStrategy,
} from '@cipherstash/auth/wasm-inline'
import {
  decrypt as wasmDecrypt,
  encrypt as wasmEncrypt,
  isEncrypted as wasmIsEncrypted,
  newClient as wasmNewClient,
} from '@cipherstash/protect-ffi/wasm-inline'
import {
  buildEncryptConfig,
  type CastAs,
  type EncryptConfig,
  EncryptedColumn,
  EncryptedField,
  type EncryptedTable,
  type EncryptedTableColumn,
  encryptConfigSchema,
  toEqlCastAs,
} from '@/schema'
import type { Encrypted, EncryptOptions } from '@/types'

// -----------------------------------------------------------------------
// Schema + type re-exports
// -----------------------------------------------------------------------

// Auth strategies for `config.strategy` — `OidcFederationStrategy` for
// per-user identity-bound encryption, `AccessKeyStrategy` for M2M / CI.
// Re-exported so edge consumers don't need a separate `@cipherstash/auth`
// import (pair `OidcFederationStrategy` with `cookieStore` from
// `@cipherstash/auth/cookies` for cross-invocation token caching).
export {
  AccessKeyStrategy,
  OidcFederationStrategy,
} from '@cipherstash/auth/wasm-inline'
export type {
  EncryptedColumn,
  EncryptedField,
  EncryptedTable,
  EncryptedTableColumn,
  InferEncrypted,
  InferPlaintext,
} from '@/schema'
export {
  encryptedColumn,
  encryptedField,
  encryptedTable,
} from '@/schema'
export type { Encrypted } from '@/types'

/** Re-exported convenience predicate — same as the raw protect-ffi one. */
export function isEncrypted(value: unknown): boolean {
  return wasmIsEncrypted(value as never)
}

// Note: the raw `newClient` / `encrypt` / `decrypt` from
// `@cipherstash/protect-ffi/wasm-inline` are intentionally NOT
// re-exported. The raw `newClient` does not normalise SDK-facing
// `cast_as` values (see `normalizeCastAs` below) and a re-export would
// invite consumers to build configs that this normaliser rejects. Import
// those names directly from their source package if you need raw access.

// -----------------------------------------------------------------------
// High-level `Encryption` factory + client.
// -----------------------------------------------------------------------

/**
 * The plaintext shape accepted by `encrypt` and returned by `decrypt`.
 * Mirrors protect-ffi's `JsPlaintext` (recursive: arrays of any of
 * these are valid). Re-defined here so the wasm-inline `.d.ts` doesn't
 * pull in the Node-only protect-ffi types.
 */
export type WasmPlaintext =
  | string
  | number
  | boolean
  | null
  | Record<string, unknown>
  | WasmPlaintext[]

/**
 * Config for {@link Encryption} on the WASM entry point.
 *
 * The workspace CRN is the single source of truth for workspace
 * identity and deployment region — matching the Node entry and
 * protect-ffi 0.25+, which read `CS_WORKSPACE_CRN` and no longer
 * consult a separate `CS_REGION`. The CRN is passed straight to the
 * underlying `AccessKeyStrategy`, which derives the region from it, so
 * there is no `region` field to keep in sync.
 *
 * For service-to-service / CI use, pass `accessKey` plus the workspace
 * `clientId` / `clientKey` and we construct an `AccessKeyStrategy` for
 * you. To plug in a custom token store (cookies on Supabase Edge, KV on
 * Cloudflare Workers, …) or to bind encryption to an end user, build the
 * strategy yourself — `AccessKeyStrategy` or `OidcFederationStrategy` —
 * and hand it to `config.strategy` instead. A pre-built strategy already
 * carries the CRN, so `workspaceCrn` is optional on that path.
 */
export type WasmClientConfig = {
  /** Workspace client identifier — required by the WASM client. */
  clientId: string
  /** Workspace client key — required by the WASM client. */
  clientKey: string
  // Provide exactly one of `accessKey` (we build the strategy) or a
  // pre-built `strategy` — never both, never neither.
} & (
  | {
      /**
       * CipherStash workspace CRN, e.g.
       * `"crn:ap-southeast-2.aws:my-workspace-id"`. Required on the
       * access-key path — it is the single source of truth for workspace
       * identity and `AccessKeyStrategy` derives the region from it.
       */
      workspaceCrn: string
      accessKey: string
      strategy?: never
    }
  | {
      /**
       * Optional on the strategy path. A pre-built `strategy` (e.g.
       * `OidcFederationStrategy.create(workspaceCrn, …)`) already
       * encapsulates the workspace CRN and region, so the SDK never reads
       * this — supply it if convenient, omit it otherwise.
       */
      workspaceCrn?: string
      accessKey?: never
      strategy: WasmAuthStrategy
    }
)

/**
 * Any auth strategy accepted on the WASM path. Both expose
 * `getToken(): Promise<{ token }>`, which is all protect-ffi's WASM
 * `newClient` requires:
 *
 * - {@link AccessKeyStrategy} — static M2M / CI access key.
 * - {@link OidcFederationStrategy} — federates an end-user OIDC JWT into a
 *   CTS service token, for per-user identity-bound encryption.
 */
export type WasmAuthStrategy = AccessKeyStrategy | OidcFederationStrategy

export type WasmEncryptionConfig = {
  schemas: [
    EncryptedTable<EncryptedTableColumn>,
    ...EncryptedTable<EncryptedTableColumn>[],
  ]
  config: WasmClientConfig
}

/**
 * Internal token used to gate the {@link WasmEncryptionClient}
 * constructor. Symbols are unique by reference, so external code can't
 * forge one even if they recreate `WasmEncryptionClient` via type
 * inspection.
 */
const INTERNAL_CONSTRUCT = Symbol('cs-wasm-client')

/**
 * WASM encryption client. Returned by {@link Encryption}.
 *
 * Wraps an opaque `wasmNewClient` handle and exposes a minimal
 * `encrypt` / `decrypt` surface. Larger surface (bulk, query, model
 * helpers) lives on the Node entry — port lazily as Deno / edge
 * consumers demand it.
 *
 * Construct via {@link Encryption} — the constructor is private to
 * prevent callers from wrapping arbitrary objects in this type.
 */
export class WasmEncryptionClient {
  /** @internal */
  private readonly client: unknown

  /**
   * @internal Gated by the module-scoped {@link INTERNAL_CONSTRUCT}
   * symbol: external callers can't obtain it, so {@link Encryption} is
   * effectively the only constructor. (A `private` constructor would
   * block {@link Encryption} too, since it lives outside the class.)
   */
  constructor(token: symbol, client: unknown) {
    if (token !== INTERNAL_CONSTRUCT) {
      throw new Error(
        '[encryption]: WasmEncryptionClient cannot be constructed directly — use the Encryption() factory.',
      )
    }
    this.client = client
  }

  async encrypt(
    plaintext: WasmPlaintext,
    opts: EncryptOptions,
  ): Promise<Encrypted> {
    const ffiOpts = {
      plaintext,
      table: opts.table.tableName,
      column: getColumnName(opts.column),
    }
    return (await wasmEncrypt(
      this.client as never,
      ffiOpts as never,
    )) as Encrypted
  }

  async decrypt(encrypted: Encrypted): Promise<WasmPlaintext> {
    return (await wasmDecrypt(
      this.client as never,
      {
        ciphertext: encrypted,
      } as never,
    )) as WasmPlaintext
  }

  isEncrypted(value: unknown): boolean {
    return wasmIsEncrypted(value as never)
  }
}

/**
 * Initialize a WASM-backed encryption client.
 *
 * Mirrors the Node entry's {@link import('./encryption').Encryption}
 * factory, but constructs the protect-ffi client via the WASM strategy
 * API. Use from Deno / Edge / Workers / Bun.
 */
export async function Encryption(
  config: WasmEncryptionConfig,
): Promise<WasmEncryptionClient> {
  const { schemas, config: clientConfig } = config

  if (!schemas.length) {
    throw new Error(
      '[encryption]: At least one encryptedTable must be provided to initialize the encryption client',
    )
  }

  const encryptConfig: EncryptConfig = encryptConfigSchema.parse(
    buildEncryptConfig(...schemas),
  )

  const strategy = resolveStrategy(clientConfig)

  // protect-ffi 0.25 takes a single options object with the strategy
  // nested under `strategy` (0.24 passed the strategy as a separate
  // first argument).
  const client = await wasmNewClient({
    strategy,
    encryptConfig: normalizeCastAs(encryptConfig),
    clientId: clientConfig.clientId,
    clientKey: clientConfig.clientKey,
  } as never)

  // `INTERNAL_CONSTRUCT` is module-scoped, so this factory is the only
  // code that can build a `WasmEncryptionClient` — external callers hit
  // the constructor guard.
  return new WasmEncryptionClient(INTERNAL_CONSTRUCT, client)
}

/**
 * Convert SDK-facing `cast_as` values (`'string'`, `'number'`, …) to the
 * EQL-native variants (`'text'`, `'double'`, …) that the WASM
 * `newClient` accepts.
 *
 * The Node entry of protect-ffi performs this normalization internally
 * via `normalizeEncryptConfig.js`; the WASM bindings do not. Without
 * this, the WASM client rejects an `encryptedColumn('email')` (which
 * defaults to `cast_as: 'string'`) with
 * `unknown variant `string`, expected one of `big_int`, …`.
 *
 * `toEqlCastAs` is exhaustive over the current `CastAs` union; if a new
 * SDK-facing variant is added without updating that switch, this
 * function throws synchronously at startup with a clear message rather
 * than handing `undefined` to the WASM serde (which surfaces as an
 * opaque `unknown variant 'null'` error).
 *
 * @internal exported for unit-test coverage of the drift-guard branch.
 */
export function normalizeCastAs(config: EncryptConfig): unknown {
  const tables: Record<string, Record<string, unknown>> = {}
  for (const [tableName, columns] of Object.entries(config.tables)) {
    const normalised: Record<string, unknown> = {}
    for (const [colName, col] of Object.entries(columns)) {
      if (col.cast_as) {
        const eqlCastAs = toEqlCastAs(col.cast_as as CastAs)
        if (eqlCastAs === undefined) {
          throw new Error(
            `[encryption]: unrecognised cast_as value "${col.cast_as}" on ${tableName}.${colName} — update toEqlCastAs() to map it to an EQL variant.`,
          )
        }
        normalised[colName] = { ...col, cast_as: eqlCastAs }
      } else {
        normalised[colName] = col
      }
    }
    tables[tableName] = normalised
  }
  return { ...config, tables }
}

function getColumnName(col: EncryptOptions['column']): string {
  if (col instanceof EncryptedColumn || col instanceof EncryptedField) {
    return col.getName()
  }
  throw new Error(
    '[encryption]: opts.column must be an EncryptedColumn or EncryptedField',
  )
}

/**
 * Resolve the auth strategy for the WASM client from its config: an explicit
 * `config.strategy`, or — for the access-key path — an `AccessKeyStrategy`
 * built from the workspace CRN (region derived from it inside
 * `@cipherstash/auth`). `strategy` and `accessKey` are mutually exclusive.
 *
 * @internal exported for offline unit coverage of the strategy wiring; the
 * gated Deno e2e (`e2e/wasm/roundtrip.test.ts`) is the only other exercise of
 * this path and it skips without real `CS_*` secrets.
 */
export function resolveStrategy(cfg: WasmClientConfig): WasmAuthStrategy {
  // The discriminated union rejects `accessKey` + `strategy` together at
  // compile time, but JS callers (Deno / plain JS) bypass that — guard at
  // runtime so a conflicting config fails loudly instead of silently
  // preferring one.
  if (cfg.strategy && cfg.accessKey) {
    throw new Error(
      '[encryption]: `config.strategy` and `config.accessKey` are mutually exclusive — pass exactly one.',
    )
  }
  if (cfg.strategy) return cfg.strategy
  // No strategy → the access-key arm, where `workspaceCrn` and `accessKey`
  // are both required (and so present at runtime); the union widens their
  // static types to `string | undefined`, hence the casts.
  // `AccessKeyStrategy.create` takes the full workspace CRN — the region is
  // derived from it inside `@cipherstash/auth`, so the CRN stays the single
  // source of truth with no manual region split.
  return AccessKeyStrategy.create(
    cfg.workspaceCrn as string,
    cfg.accessKey as string,
  )
}
