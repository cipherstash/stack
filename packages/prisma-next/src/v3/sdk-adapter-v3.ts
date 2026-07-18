/**
 * Adapt the `@cipherstash/stack` EQL v3 client (the
 * `TypedEncryptionClient` returned by `EncryptionV3`) to the
 * framework-native `CipherstashSdk` shape consumed by
 * `createCipherstashV3RuntimeDescriptor({ sdk })` and
 * `bulkEncryptMiddlewareV3(sdk)`.
 *
 * The framework calls into the SDK with `(table, column)` routing-key
 * strings; the adapter resolves those strings back to the typed v3
 * `EncryptedTable` / column-builder objects via a registry built from
 * the supplied schemas, keyed on the **physical** column name
 * (post-`@map`, via `getName()`).
 *
 * ## Two encryption paths behind one `bulkEncrypt` seam
 *
 * v3 has two kinds of encrypted values, and the `values` array of a
 * `bulkEncrypt` call can carry both (the middleware groups params by
 * `(table, column)`, and an `UPDATE … SET col = $1 WHERE col = $2`
 * puts a storage value and a query term in one group):
 *
 *   - **Storage values** (write path): raw plaintexts. Encrypted via
 *     the client's storage `bulkEncrypt` — one crossing per call.
 *   - **Query terms**: envelope instances marked by the v3 operators
 *     (`markV3QueryTerm`, see `./query-term`). Encrypted via the
 *     client's `encryptQuery` with the marked `queryType`, minting a
 *     CIPHERTEXT-FREE term the `eql_v3.query_<domain>` cast needs.
 *     Scalar flavours (`equality` / `orderAndRange` / `freeTextSearch`)
 *     batch all same-flavour terms into ONE `encryptQuery(terms[])`
 *     crossing — the same batch surface `@cipherstash/stack-drizzle`'s
 *     v3 `inArray` uses. `searchableJson` terms go through the single
 *     `encryptQuery(value, { queryType: 'searchableJson' })` form,
 *     mirroring stack-drizzle's JSON containment path (the batch
 *     operation is scalar-only — it never produces a ste_vec term).
 *
 * Results are reassembled position-stable, so the middleware's
 * write-back aligns index-for-index with its collected targets.
 *
 * Unlike the v2 adapter there is no plaintext coercion at this
 * boundary: protect-ffi in v3/eqlVersion-3 mode natively handles
 * `bigint` (bounds-checked int8) and `Date` plaintexts, so values pass
 * through unchanged and the client validates against the column's
 * domain.
 */

import type {
  AnyEncryptedV3Column,
  AnyV3Table,
} from '@cipherstash/stack/eql/v3'
import { EncryptedEnvelopeBase } from '../execution/envelope-base'
import type { CipherstashRoutingKey, CipherstashSdk } from '../execution/sdk'
import { type V3QueryTermType, v3QueryTermTypeOf } from './query-term'

// Mirrors `@byteslice/result`'s discriminated `Result<S, F>` shape
// (which `@cipherstash/stack` returns) without forcing the package to
// depend on `@byteslice/result` directly. Same pattern as the v2
// adapter.
type StackResult<T> =
  | { readonly failure?: never; readonly data: T }
  | { readonly failure: { readonly message: string } }

/**
 * Minimal structural view of the stack v3 client this adapter drives —
 * satisfied by the `TypedEncryptionClient` that `EncryptionV3` returns
 * (whatever its schema tuple) AND by a hand-rolled test double, neither
 * needing a cast.
 *
 * `encryptQuery`'s `never` operands are deliberate (same rationale as
 * `@cipherstash/stack-drizzle`'s `OperandEncryptionClient`): the real
 * client's `encryptQuery` is generic — `queryType` is constrained to
 * the column's own query types — which a concrete signature here cannot
 * match. `never` params keep the structural surface satisfiable by that
 * generic method; the call sites cast their real operands.
 */
export interface CipherstashV3Client {
  bulkEncrypt(
    payload: ReadonlyArray<{ plaintext: unknown }>,
    opts: { table: AnyV3Table; column: AnyEncryptedV3Column },
  ): PromiseLike<StackResult<ReadonlyArray<{ data: unknown }>>>
  decrypt(encrypted: unknown): PromiseLike<StackResult<unknown>>
  bulkDecrypt(
    payloads: ReadonlyArray<{ data: unknown }>,
  ): PromiseLike<
    StackResult<
      ReadonlyArray<{ readonly data?: unknown; readonly error?: unknown }>
    >
  >
  encryptQuery(plaintext: never, opts: never): PromiseLike<StackResult<unknown>>
  encryptQuery(terms: never): PromiseLike<StackResult<ReadonlyArray<unknown>>>
}

interface V3RegistryEntry {
  readonly table: AnyV3Table
  readonly columns: ReadonlyMap<string, AnyEncryptedV3Column>
}

/** One value slot awaiting encryption, with its position in `values`. */
interface PendingSlot {
  readonly index: number
  readonly plaintext: unknown
}

/**
 * Build a `CipherstashSdk` from a stack v3 client plus the v3 schemas
 * it was constructed with.
 *
 * `schemas` should be the exact `AnyV3Table[]` passed to
 * `EncryptionV3({ schemas })` (typically the return value of
 * `deriveStackSchemasV3`). The adapter uses it to translate framework
 * `(table, column)` routing-key strings back to the typed schema
 * objects the client's operations expect.
 */
export function createCipherstashV3Sdk(
  client: CipherstashV3Client,
  schemas: ReadonlyArray<AnyV3Table>,
): CipherstashSdk {
  const registry = new Map<string, V3RegistryEntry>()
  for (const table of schemas) {
    const columns = new Map<string, AnyEncryptedV3Column>()
    for (const builder of Object.values(table.columnBuilders)) {
      columns.set(builder.getName(), builder)
    }
    registry.set(table.tableName, { table, columns })
  }

  function lookup(routingKey: CipherstashRoutingKey): {
    table: AnyV3Table
    column: AnyEncryptedV3Column
  } {
    const entry = registry.get(routingKey.table)
    if (entry === undefined) {
      throw new Error(
        `cipherstash v3 SDK adapter: routing-key table "${routingKey.table}" is not in the v3 schemas. ` +
          'If you derived your schemas with `deriveStackSchemasV3(contractJson)`, this means the contract has no ' +
          'v3 cipherstash columns on that table — check `prisma/schema.prisma` and re-emit the contract.',
      )
    }
    const column = entry.columns.get(routingKey.column)
    if (column === undefined) {
      throw new Error(
        `cipherstash v3 SDK adapter: routing-key column "${routingKey.column}" is not on v3 table "${routingKey.table}". ` +
          'Routing keys use physical column names (post-`@map`). Check `prisma/schema.prisma` and re-emit the contract.',
      )
    }
    return { table: entry.table, column }
  }

  return {
    async bulkEncrypt({ values, routingKey }) {
      const { table, column } = lookup(routingKey)
      const results = new Array<unknown>(values.length)

      // Partition the batch: unmarked values take the storage path;
      // marked envelopes are query terms, grouped by flavour.
      const storage: PendingSlot[] = []
      const scalarTerms = new Map<
        Exclude<V3QueryTermType, 'searchableJson'>,
        PendingSlot[]
      >()
      const jsonTerms: PendingSlot[] = []

      values.forEach((value, index) => {
        const queryType = v3QueryTermTypeOf(value)
        if (
          queryType === undefined ||
          !(value instanceof EncryptedEnvelopeBase)
        ) {
          storage.push({ index, plaintext: value })
          return
        }
        const plaintext = value.expose().plaintext
        if (plaintext === undefined) {
          throw new Error(
            `cipherstash v3 SDK adapter: "${queryType}" query-term envelope for ` +
              `"${routingKey.table}"."${routingKey.column}" has no plaintext to encrypt. ` +
              'Operator operands must be plaintext values or envelopes built with `Encrypted*.from(...)`.',
          )
        }
        if (queryType === 'searchableJson') {
          jsonTerms.push({ index, plaintext })
        } else {
          const group = scalarTerms.get(queryType)
          if (group === undefined) {
            scalarTerms.set(queryType, [{ index, plaintext }])
          } else {
            group.push({ index, plaintext })
          }
        }
      })

      if (storage.length > 0) {
        const result = await client.bulkEncrypt(
          storage.map((slot) => ({ plaintext: slot.plaintext })),
          { table, column },
        )
        const data = unwrap(result, 'bulkEncrypt')
        if (data.length !== storage.length) {
          throw new Error(
            `cipherstash v3 bulkEncrypt: client returned ${data.length} ciphertexts for ${storage.length} plaintexts ` +
              `on "${routingKey.table}"."${routingKey.column}".`,
          )
        }
        storage.forEach((slot, i) => {
          results[slot.index] = data[i]?.data
        })
      }

      for (const [queryType, group] of scalarTerms) {
        // ONE batch crossing per scalar flavour — the position-stable
        // `encryptQuery(terms[])` surface stack-drizzle's v3 `inArray`
        // uses.
        const terms = group.map((slot) => ({
          value: slot.plaintext,
          table,
          column,
          queryType,
        }))
        // Cast rationale: `CipherstashV3Client.encryptQuery` declares
        // `never` operands so the real client's GENERIC method satisfies
        // the structural surface (see the interface doc); the concrete
        // operand is re-widened at each call site.
        // biome-ignore lint/plugin: deliberate bridge into the structural `never`-operand surface (rationale above)
        const result = await client.encryptQuery(terms as never)
        const data = unwrap(result, `encryptQuery(${queryType})`)
        if (data.length !== group.length) {
          throw new Error(
            `cipherstash v3 encryptQuery(${queryType}): client returned ${data.length} terms for ${group.length} values ` +
              `on "${routingKey.table}"."${routingKey.column}".`,
          )
        }
        group.forEach((slot, i) => {
          const term = data[i]
          if (term == null) {
            throw new Error(
              `cipherstash v3 encryptQuery(${queryType}): client returned a null term for a non-null value ` +
                `on "${routingKey.table}"."${routingKey.column}".`,
            )
          }
          results[slot.index] = term
        })
      }

      // JSON containment terms go through the single-call path — the
      // batch operation is scalar-only (it never mints ste_vec terms);
      // this mirrors stack-drizzle's JSON containment usage exactly.
      await Promise.all(
        jsonTerms.map(async (slot) => {
          // Cast rationale: see the scalar branch above. The two operands sit
          // on separate argument lines, so each cast needs its own ignore —
          // a single comment above the call reaches neither.
          const result = await client.encryptQuery(
            // biome-ignore lint/plugin: deliberate bridge into the structural `never`-operand surface (rationale above)
            slot.plaintext as never,
            // biome-ignore lint/plugin: deliberate bridge into the structural `never`-operand surface (rationale above)
            { table, column, queryType: 'searchableJson' } as never,
          )
          const term = unwrap(result, 'encryptQuery(searchableJson)')
          if (term == null) {
            throw new Error(
              'cipherstash v3 encryptQuery(searchableJson): client returned a null term for a non-null needle ' +
                `on "${routingKey.table}"."${routingKey.column}".`,
            )
          }
          results[slot.index] = term
        }),
      )

      return results
    },

    async decrypt({ ciphertext }) {
      const result = await client.decrypt(
        ensureV3Payload(ciphertext, 'decrypt'),
      )
      return asSdkPlaintext(unwrap(result, 'decrypt'))
    },

    async bulkDecrypt({ ciphertexts }) {
      const payload = ciphertexts.map((data, index) => ({
        data: ensureV3Payload(data, 'bulkDecrypt', index),
      }))
      const result = await client.bulkDecrypt(payload)
      const data = unwrap(result, 'bulkDecrypt')
      // Same cardinality contract as bulkEncrypt above: a truncated
      // response would silently misalign plaintexts with `ciphertexts`.
      if (data.length !== ciphertexts.length) {
        throw new Error(
          `cipherstash v3 bulkDecrypt: client returned ${data.length} plaintexts for ${ciphertexts.length} ciphertexts.`,
        )
      }
      return data.map((entry) => {
        if ('error' in entry && entry.error !== undefined) {
          throw new Error(
            `cipherstash v3 bulkDecrypt entry failed: ${String(entry.error)}`,
          )
        }
        return asSdkPlaintext(entry.data)
      })
    },
  }
}

function unwrap<T>(result: StackResult<T>, op: string): T {
  if (result.failure) {
    throw new Error(`cipherstash v3 ${op} failed: ${result.failure.message}`)
  }
  return result.data
}

/**
 * A v3 cell is a `public.eql_v3_*` domain over `jsonb`, so a decodable
 * ciphertext is always a parsed JSON document (`v3FromDriver` output) —
 * reject primitives early with a diagnostic instead of letting the FFI
 * fail opaquely. Deliberately shallower than the v2 adapter's
 * `i: { t, c }` envelope check: the v3 payload shape is owned by
 * protect-ffi's eqlVersion-3 wire and validated there.
 */
function ensureV3Payload(
  value: unknown,
  kind: 'decrypt' | 'bulkDecrypt',
  index?: number,
): object {
  if (typeof value !== 'object' || value === null) {
    const where = index === undefined ? '' : ` at index ${index}`
    throw new Error(
      `cipherstash v3 ${kind}: ciphertext${where} is not a valid EQL v3 payload ` +
        '(expected the parsed JSONB document stored in the public.eql_v3_* column).',
    )
  }
  return value
}

// The framework's `CipherstashSdk.decrypt` is typed `Promise<string>`
// but every envelope's `parseDecryptedValue` hook narrows the raw value
// to its concrete plaintext type. Forwarding through this cast keeps
// the codec-side polymorphism intact across the SDK contract (same
// pattern as the v2 adapter).
function asSdkPlaintext(value: unknown): string {
  return value as string
}
