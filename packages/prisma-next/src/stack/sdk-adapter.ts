/**
 * Adapt `@cipherstash/stack`'s `EncryptionClient` to the
 * framework-native `CipherstashSdk` shape consumed by
 * `createCipherstashRuntimeDescriptor({ sdk })` and
 * `bulkEncryptMiddleware(sdk)`.
 *
 * The framework calls into the SDK with `(table, column)` routing-key
 * strings — it doesn't know about stack's typed `EncryptedTable` /
 * `EncryptedColumn` objects. The adapter resolves those strings back
 * to the typed objects via a registry built from the supplied
 * schemas. The registry is keyed on the **physical** column name
 * (post-`@map`), matching how the framework's bulk-encrypt middleware
 * derives routing keys from the lowered AST.
 *
 * Plaintext coercion at the boundary:
 *
 *   - `bigint → number` (ZeroKMS's `big_int` cast accepts numeric
 *     plaintexts only; values must fit in the JS safe-integer range;
 *     overflow throws eagerly).
 *   - `Date → ISO 8601 string` (both ZeroKMS and the EQL bundle accept
 *     the textual form).
 *
 * Every other JS value type is passed through to the stack SDK as-is;
 * the stack SDK then validates against its declared per-column
 * `dataType()` on each `bulkEncrypt` call.
 */

import { type Encrypted, isEncryptedPayload } from '@cipherstash/stack'
import type { EncryptionClient } from '@cipherstash/stack/client'
import {
  EncryptedColumn,
  EncryptedField,
  type EncryptedTable,
  type EncryptedTableColumn,
} from '@cipherstash/stack/schema'

import type { CipherstashRoutingKey, CipherstashSdk } from '../execution/sdk'

// `JsPlaintext` is the input type `@cipherstash/stack`'s `bulkEncrypt`
// accepts for non-bigint, non-Date values. Redeclared locally because
// `@cipherstash/stack` does not re-export it through its public surface.
type JsPlaintext =
  | string
  | number
  | boolean
  | { [key: string]: unknown }
  | JsPlaintext[]

type StackColumn = EncryptedColumn | EncryptedField

interface RegistryEntry {
  readonly table: EncryptedTable<EncryptedTableColumn>
  readonly columns: Readonly<Record<string, StackColumn>>
}

/**
 * Build a `CipherstashSdk` from an initialised `@cipherstash/stack`
 * `EncryptionClient` plus the schemas it was constructed with.
 *
 * `schemas` should be the exact `EncryptedTable[]` array passed to
 * `Encryption({ schemas })` (or its return value from
 * {@link deriveStackSchemas}). The adapter uses it to translate
 * framework `(table, column)` routing-key strings back to the typed
 * schema objects the stack SDK's `bulkEncrypt(...)` expects in
 * `{ column, table }`.
 */
export function createCipherstashSdk(
  encryptionClient: EncryptionClient,
  schemas: ReadonlyArray<EncryptedTable<EncryptedTableColumn>>,
): CipherstashSdk {
  const registry = buildRegistry(schemas)

  return {
    async bulkEncrypt({ values, routingKey }) {
      const { table, column } = lookup(registry, routingKey)
      const result = await encryptionClient.bulkEncrypt(
        values.map((plaintext) => ({ plaintext: toJsPlaintext(plaintext) })),
        { column, table },
      )
      return unwrap(result, 'bulkEncrypt').map((entry) => entry.data)
    },

    async bulkDecrypt({ ciphertexts }) {
      const payload = ciphertexts.map((data, index) => ({
        data: ensureEncryptedEnvelope(data, 'bulkDecrypt', index),
      }))
      const result = await encryptionClient.bulkDecrypt(payload)
      return unwrap(result, 'bulkDecrypt').map(unwrapBulkDecryptEntry)
    },

    async decrypt({ ciphertext }) {
      const result = await encryptionClient.decrypt(
        ensureEncryptedEnvelope(ciphertext, 'decrypt'),
      )
      return asSdkPlaintext(unwrap(result, 'decrypt'))
    },
  }
}

// Mirrors `@byteslice/result`'s discriminated `Result<S, F>` shape
// (which `@cipherstash/stack` returns) without forcing the package to
// depend on `@byteslice/result` directly.
type StackResult<T> =
  | { readonly failure?: never; readonly data: T }
  | { readonly failure: { readonly message: string } }

function unwrap<T>(result: StackResult<T>, op: string): T {
  if (result.failure) {
    throw new Error(`cipherstash ${op} failed: ${result.failure.message}`)
  }
  return result.data
}

function unwrapBulkDecryptEntry(entry: {
  data?: unknown
  error?: unknown
}): string {
  if ('error' in entry && entry.error !== undefined) {
    throw new Error(
      `cipherstash bulkDecrypt entry failed: ${String(entry.error)}`,
    )
  }
  return asSdkPlaintext(entry.data)
}

function buildRegistry(
  schemas: ReadonlyArray<EncryptedTable<EncryptedTableColumn>>,
): Map<string, RegistryEntry> {
  const registry = new Map<string, RegistryEntry>()
  for (const table of schemas) {
    const columns: Record<string, StackColumn> = {}
    // `encryptedTable(name, builders)` intersects each column builder
    // onto the table instance under its own key, so iterating own
    // enumerable properties recovers them.
    for (const [key, value] of Object.entries(table)) {
      if (value instanceof EncryptedColumn || value instanceof EncryptedField) {
        columns[key] = value
      }
    }
    registry.set(table.tableName, { table, columns })
  }
  return registry
}

function lookup(
  registry: Map<string, RegistryEntry>,
  routingKey: CipherstashRoutingKey,
): { table: EncryptedTable<EncryptedTableColumn>; column: StackColumn } {
  const entry = registry.get(routingKey.table)
  if (entry === undefined) {
    throw new Error(
      `cipherstash SDK adapter: routing-key table "${routingKey.table}" is not in the stack schemas. ` +
        'If you derived your schemas with `deriveStackSchemas(contractJson)`, this means the contract has no ' +
        'cipherstash columns on that table — check `prisma/schema.prisma` and re-emit the contract.',
    )
  }
  const column = entry.columns[routingKey.column]
  if (column === undefined) {
    throw new Error(
      `cipherstash SDK adapter: routing-key column "${routingKey.column}" is not on stack table "${routingKey.table}". ` +
        'Routing keys use physical column names (post-`@map`). Check `prisma/schema.prisma` and re-emit the contract.',
    )
  }
  return { table: entry.table, column }
}

function ensureEncryptedEnvelope(
  value: unknown,
  kind: 'decrypt' | 'bulkDecrypt',
  index?: number,
): Encrypted {
  // `isEncryptedPayload` checks the v1/v2 envelope basics (object,
  // numeric `v`, `i` object, `c` or `sv` present). We additionally
  // require the EQL v2 `i: { t, c }` substructure because that's
  // what the framework's bulk-decrypt path expects.
  const valid =
    isEncryptedPayload(value) &&
    typeof (value as { i: { t?: unknown; c?: unknown } }).i === 'object' &&
    't' in (value as { i: object }).i &&
    'c' in (value as { i: object }).i
  if (!valid) {
    const where = index === undefined ? '' : ` at index ${index}`
    throw new Error(
      `cipherstash ${kind}: ciphertext${where} is not a valid EQL v2 envelope ` +
        '(expected an object with `i: { t, c }`, numeric `v`, and `c` or `sv`).',
    )
  }
  return value
}

function toJsPlaintext(value: unknown): JsPlaintext {
  if (typeof value === 'bigint') {
    // ZeroKMS's `big_int` cast accepts only numeric plaintexts. Throw
    // eagerly on overflow rather than truncating silently on the wire.
    if (
      value > BigInt(Number.MAX_SAFE_INTEGER) ||
      value < BigInt(Number.MIN_SAFE_INTEGER)
    ) {
      throw new Error(
        `cipherstash bigint plaintext ${value} exceeds Number.MAX_SAFE_INTEGER; ` +
          'ZeroKMS does not accept string plaintexts for the big_int cast type.',
      )
    }
    return Number(value)
  }
  if (value instanceof Date) return value.toISOString()
  return value as JsPlaintext
}

// The framework's `CipherstashSdk.decrypt` is typed `Promise<string>`
// but every envelope's `parseDecryptedValue` hook narrows the raw value
// to its concrete plaintext type. Forwarding through this cast keeps the
// codec-side polymorphism intact across the SDK contract.
function asSdkPlaintext(value: unknown): string {
  return value as string
}
