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
 *     region: "ap-southeast-2.aws",
 *     accessKey: Deno.env.get("CS_CLIENT_ACCESS_KEY")!,
 *     clientId: Deno.env.get("CS_CLIENT_ID")!,
 *     clientKey: Deno.env.get("CS_CLIENT_KEY")!,
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
 * For lower-level access, the raw `@cipherstash/protect-ffi/wasm-inline`
 * functions and the `@cipherstash/auth/wasm-inline` strategy are
 * re-exported below.
 */

import {
  decrypt as wasmDecrypt,
  encrypt as wasmEncrypt,
  isEncrypted as wasmIsEncrypted,
  newClient as wasmNewClient,
} from '@cipherstash/protect-ffi/wasm-inline'
import { AccessKeyStrategy } from '@cipherstash/auth/wasm-inline'
import {
  type CastAs,
  type EncryptConfig,
  type EncryptedTable,
  type EncryptedTableColumn,
  buildEncryptConfig,
  encryptConfigSchema,
  toEqlCastAs,
} from '@/schema'
import { EncryptedColumn, EncryptedField } from '@/schema'
import type { Encrypted, EncryptOptions } from '@/types'

// -----------------------------------------------------------------------
// Re-exports — direct passthrough for consumers who want the raw API.
// -----------------------------------------------------------------------

export {
  encryptedColumn,
  encryptedField,
  encryptedTable,
} from '@/schema'

export type {
  EncryptedColumn,
  EncryptedField,
  EncryptedTable,
  EncryptedTableColumn,
  InferEncrypted,
  InferPlaintext,
} from '@/schema'

export type { Encrypted } from '@/types'

export {
  decrypt as decryptRaw,
  encrypt as encryptRaw,
  isEncrypted,
  newClient as newClientRaw,
} from '@cipherstash/protect-ffi/wasm-inline'

export { AccessKeyStrategy } from '@cipherstash/auth/wasm-inline'

// -----------------------------------------------------------------------
// High-level `Encryption` factory + client.
// -----------------------------------------------------------------------

/** Default region used when `WasmClientConfig.region` is unset. */
const DEFAULT_REGION = 'ap-southeast-2.aws'

/**
 * Config for {@link Encryption} on the WASM entry point.
 *
 * Unlike the Node entry, the WASM path requires an explicit auth
 * strategy. For service-to-service / CI use, pass an `accessKey` and we
 * construct an {@link AccessKeyStrategy} for you; alternatively, pass
 * your own pre-built `strategy` to use OAuth-style flows or a custom
 * token store.
 */
export type WasmClientConfig = {
  /** CipherStash region, e.g. `"ap-southeast-2.aws"`. Defaults to ap-southeast-2.aws. */
  region?: string
  /** Static access key. Mutually exclusive with `strategy`. */
  accessKey?: string
  /** Pre-built auth strategy (e.g. `AccessKeyStrategy.create(...)` with a custom token store). */
  strategy?: { getToken(): Promise<unknown> }
  /** Workspace credentials. */
  clientId?: string
  clientKey?: string
}

export type WasmEncryptionConfig = {
  schemas: [
    EncryptedTable<EncryptedTableColumn>,
    ...EncryptedTable<EncryptedTableColumn>[],
  ]
  config: WasmClientConfig
}

/**
 * WASM encryption client. Returned by {@link Encryption}.
 *
 * Wraps an opaque {@link wasmNewClient} handle and exposes a minimal
 * `encrypt` / `decrypt` surface. Larger surface (bulk, query, model
 * helpers) lives on the Node entry — port lazily as Deno / edge
 * consumers demand it.
 */
export class WasmEncryptionClient {
  /** @internal */
  private readonly client: unknown

  constructor(client: unknown) {
    this.client = client
  }

  async encrypt(
    plaintext: string | number | boolean | Record<string, unknown>,
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

  async decrypt(encrypted: Encrypted): Promise<string | number | boolean | Record<string, unknown>> {
    return (await wasmDecrypt(this.client as never, {
      ciphertext: encrypted,
    } as never)) as string | number | boolean | Record<string, unknown>
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

  const client = await wasmNewClient(strategy as never, {
    encryptConfig: normalizeCastAs(encryptConfig),
    clientId: clientConfig.clientId,
    clientKey: clientConfig.clientKey,
  } as never)

  return new WasmEncryptionClient(client)
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
 */
function normalizeCastAs(config: EncryptConfig): unknown {
  const tables: Record<string, Record<string, unknown>> = {}
  for (const [tableName, columns] of Object.entries(config.tables)) {
    const normalised: Record<string, unknown> = {}
    for (const [colName, col] of Object.entries(columns)) {
      normalised[colName] = col.cast_as
        ? { ...col, cast_as: toEqlCastAs(col.cast_as as CastAs) }
        : col
    }
    tables[tableName] = normalised
  }
  return { ...config, tables }
}

function getColumnName(
  col: EncryptOptions['column'],
): string {
  if (col instanceof EncryptedColumn || col instanceof EncryptedField) {
    return col.getName()
  }
  throw new Error(
    '[encryption]: opts.column must be an EncryptedColumn or EncryptedField',
  )
}

function resolveStrategy(
  cfg: WasmClientConfig,
): { getToken(): Promise<unknown> } {
  if (cfg.strategy) return cfg.strategy
  if (cfg.accessKey) {
    return AccessKeyStrategy.create(
      cfg.region ?? DEFAULT_REGION,
      cfg.accessKey,
    )
  }
  throw new Error(
    '[encryption]: WASM entry requires either `config.strategy` or `config.accessKey`',
  )
}
