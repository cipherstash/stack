/**
 * One-call setup for `@cipherstash/prisma-next` against
 * `@cipherstash/stack`.
 *
 * Replaces the manual three-step wiring (derive schemas → construct
 * `Encryption({ schemas })` → build `CipherstashSdk` adapter → wrap
 * with `createCipherstashRuntimeDescriptor` and `bulkEncryptMiddleware`)
 * with a single async factory that returns ready-to-spread arrays for
 * `postgres<Contract>({...})`:
 *
 *   const cipherstash = await cipherstashFromStackV2({ contractJson })
 *
 *   const db = postgres<Contract>({
 *     contractJson,
 *     extensions: cipherstash.extensions,
 *     middleware:  cipherstash.middleware,
 *   })
 *
 * Override semantics: a user-supplied `schemas` array is allowed to
 * add tables the contract doesn't model. For tables the contract
 * **does** declare, the override must agree on column names,
 * `cast_as`, and the installed index set — divergence throws at
 * setup so ZeroKMS can't end up with an index set that the EQL
 * bundle's installed configuration disagrees with.
 *
 * This is the **EQL v2** entry point. For an EQL v3 contract
 * (`cipherstash/eql-v3/*` codec ids) use `cipherstashFromStack`
 * (`./from-stack-v3.ts`) — v2 and v3 are separate entry points that
 * are never co-registered in one client (decision 1b).
 */

import { Encryption } from '@cipherstash/stack'
import type { EncryptionClient } from '@cipherstash/stack/client'
import {
  type CastAs,
  type EncryptedTable,
  type EncryptedTableColumn,
  toEqlCastAs,
} from '@cipherstash/stack/schema'
import type {
  SqlMiddleware,
  SqlRuntimeExtensionDescriptor,
} from '@prisma-next/sql-runtime'

import { createCipherstashRuntimeDescriptor } from '../exports/runtime'
import { bulkEncryptMiddleware } from '../middleware/bulk-encrypt'
import { type ContractStorageView, deriveStackSchemas } from './derive-schemas'
import { createCipherstashSdk } from './sdk-adapter'

export interface CipherstashFromStackOptions {
  /** The contract.json artefact emitted by `prisma-next contract emit`. */
  readonly contractJson: ContractStorageView

  /**
   * Optional schema override. Use this to add tables the contract
   * does not model. For tables the contract **does** declare, the
   * override must match on column names, `cast_as`, and installed
   * indices — divergence throws at setup.
   */
  readonly schemas?: ReadonlyArray<EncryptedTable<EncryptedTableColumn>>

  /** Pass-through to `Encryption({ config })` (keyset overrides, logging, …). */
  readonly encryptionConfig?: Parameters<typeof Encryption>[0]['config']
}

export interface CipherstashFromStackResult {
  /** Ready to spread into `postgres<Contract>({ extensions })`. */
  readonly extensions: ReadonlyArray<SqlRuntimeExtensionDescriptor<'postgres'>>
  /** Ready to spread into `postgres<Contract>({ middleware })`. */
  readonly middleware: ReadonlyArray<SqlMiddleware>
  /** The initialised `EncryptionClient` for direct SDK access outside the ORM path. */
  readonly encryptionClient: EncryptionClient
}

export async function cipherstashFromStackV2(
  opts: CipherstashFromStackOptions,
): Promise<CipherstashFromStackResult> {
  const derived = deriveStackSchemas(opts.contractJson)
  const schemas = resolveSchemas(derived, opts.schemas)
  const [first, ...rest] = schemas
  if (first === undefined) {
    throw new Error(
      'cipherstashFromStackV2: no cipherstash columns found in contract.json AND no override `schemas` supplied. ' +
        "`@cipherstash/stack`'s `Encryption({ schemas })` requires at least one `EncryptedTable`. " +
        'Check that prisma/schema.prisma declares at least one `cipherstash.Encrypted*V2()` column and that ' +
        '`pnpm emit` has been run since the last edit.',
    )
  }

  const encryptionClient = await Encryption({
    schemas: [first, ...rest],
    ...(opts.encryptionConfig !== undefined
      ? { config: opts.encryptionConfig }
      : {}),
  })

  const sdk = createCipherstashSdk(encryptionClient, schemas)

  return {
    extensions: [createCipherstashRuntimeDescriptor({ sdk })],
    middleware: [bulkEncryptMiddleware(sdk)],
    encryptionClient,
  }
}

function resolveSchemas(
  derived: ReadonlyArray<EncryptedTable<EncryptedTableColumn>>,
  override: ReadonlyArray<EncryptedTable<EncryptedTableColumn>> | undefined,
): ReadonlyArray<EncryptedTable<EncryptedTableColumn>> {
  if (override === undefined || override.length === 0) return derived

  const derivedByName = new Map(derived.map((t) => [t.tableName, t]))
  const overrideByName = new Map(override.map((t) => [t.tableName, t]))

  for (const [tableName, derivedTable] of derivedByName) {
    const overrideTable = overrideByName.get(tableName)
    if (overrideTable === undefined) continue
    assertSchemasAgree(derivedTable, overrideTable)
  }

  return [
    ...derived,
    ...override.filter((t) => !derivedByName.has(t.tableName)),
  ]
}

function assertSchemasAgree(
  derived: EncryptedTable<EncryptedTableColumn>,
  user: EncryptedTable<EncryptedTableColumn>,
): void {
  const derivedDef = derived.build()
  const userDef = user.build()

  const derivedCols = new Set(Object.keys(derivedDef.columns))
  const userCols = new Set(Object.keys(userDef.columns))

  const missingInUser = [...derivedCols].filter((c) => !userCols.has(c)).sort()
  const extraInUser = [...userCols].filter((c) => !derivedCols.has(c)).sort()

  if (missingInUser.length > 0 || extraInUser.length > 0) {
    const parts: string[] = []
    if (missingInUser.length > 0)
      parts.push(`missing in override: [${missingInUser.join(', ')}]`)
    if (extraInUser.length > 0)
      parts.push(`extra in override: [${extraInUser.join(', ')}]`)
    divergence(
      `table "${derived.tableName}"`,
      `declares columns [${[...derivedCols].sort().join(', ')}]`,
      `declares [${[...userCols].sort().join(', ')}] (${parts.join('; ')})`,
      'Override `schemas` must match the contract on every contract-declared table; use it only to add tables the contract does not model.',
    )
  }

  for (const colName of derivedCols) {
    const d = derivedDef.columns[colName]!
    const u = userDef.columns[colName]!

    // Normalise through `toEqlCastAs` so SDK-facing aliases agree —
    // `dataType('string')` and `dataType('text')` both lower to EQL `'text'`.
    const dCast = toEqlCastAs(d.cast_as as CastAs)
    const uCast = toEqlCastAs(u.cast_as as CastAs)
    if (dCast !== uCast) {
      divergence(
        `column "${derived.tableName}"."${colName}"`,
        `declares cast_as="${d.cast_as}"`,
        `declares cast_as="${u.cast_as}" (EQL cast_as "${dCast}" vs "${uCast}")`,
        'Fix prisma/schema.prisma and re-emit the contract rather than overriding.',
      )
    }

    const derivedIndexes = indexKeys(d.indexes)
    const userIndexes = indexKeys(u.indexes)
    if (!setsEqual(derivedIndexes, userIndexes)) {
      divergence(
        `column "${derived.tableName}"."${colName}"`,
        `installs indexes [${[...derivedIndexes].sort().join(', ') || '(none)'}]`,
        `installs [${[...userIndexes].sort().join(', ') || '(none)'}]`,
        'Fix prisma/schema.prisma and re-emit the contract rather than overriding.',
      )
    }
  }
}

function divergence(
  loc: string,
  contractSide: string,
  overrideSide: string,
  hint: string,
): never {
  throw new Error(
    `cipherstashFromStackV2: schema divergence on ${loc}. Contract ${contractSide} but override ${overrideSide}. ${hint}`,
  )
}

function indexKeys(indexes: Record<string, unknown>): Set<string> {
  return new Set(Object.keys(indexes).filter((k) => indexes[k] !== undefined))
}

function setsEqual<T>(a: Set<T>, b: Set<T>): boolean {
  if (a.size !== b.size) return false
  for (const v of a) if (!b.has(v)) return false
  return true
}
