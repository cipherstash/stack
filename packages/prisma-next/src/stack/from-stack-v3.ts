/**
 * One-call setup for `@cipherstash/prisma-next` against the
 * `@cipherstash/stack` EQL v3 client — the v3-only sibling of
 * `./from-stack.ts` (decision 1b: v2 and v3 are SEPARATE entry points
 * that are never co-registered in one client; the v2
 * `cipherstashFromStackV2` is untouched by this module).
 *
 *   const cipherstash = await cipherstashFromStack({ contractJson })
 *
 *   const db = postgres<Contract>({
 *     contractJson,
 *     extensions: cipherstash.extensions,
 *     middleware:  cipherstash.middleware,
 *   })
 *
 * A v3 client is v3-only: a contract carrying a v2 cipherstash codec id
 * is the WRONG entry point (mixed v2+v3 columns in one client are
 * unsupported this release) and is a hard error rather than a silently
 * ignored column.
 *
 * Override semantics: a user-supplied `schemasV3` array is allowed to
 * add tables the contract doesn't model. For tables the contract
 * **does** declare, the override must agree on EXACT domain identity
 * per column (`integer_ord` ≠ `integer_ord_ore` even though both are
 * `cast_as: number`) — divergence throws at setup so ZeroKMS can't end
 * up minting query terms the installed domain's CHECK rejects.
 */

import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { ClientConfig } from '@cipherstash/stack/types'
import { EncryptionV3, type TypedEncryptionClient } from '@cipherstash/stack/v3'
import type {
  SqlMiddleware,
  SqlRuntimeExtensionDescriptor,
} from '@prisma-next/sql-runtime'

import { isCipherstashV3CodecId } from '../extension-metadata/constants-v3'
import { bulkEncryptMiddlewareV3 } from '../v3/bulk-encrypt-v3'
import {
  deriveStackSchemasV3,
  type V3ContractShape,
  v3ContractColumnEntries,
} from '../v3/derive-schemas-v3'
import { assertV3SchemasAgree } from '../v3/from-stack-v3-validate'
import { createCipherstashV3RuntimeDescriptor } from '../v3/runtime-v3'
import { createCipherstashV3Sdk } from '../v3/sdk-adapter-v3'

export interface CipherstashFromStackV3Options {
  /** The contract.json artefact emitted by `prisma-next contract emit`. */
  readonly contractJson: V3ContractShape

  /**
   * Optional schema override. Use this to add tables the contract does
   * not model. For tables the contract **does** declare, the override
   * must match on column names and EXACT `public.eql_v3_*` domain
   * identity — divergence throws at setup.
   */
  readonly schemasV3?: ReadonlyArray<AnyV3Table>

  /** Pass-through to `EncryptionV3({ config })` (keyset overrides, logging, …). */
  readonly encryptionConfig?: ClientConfig
}

export interface CipherstashFromStackV3Result {
  /** Ready to spread into `postgres<Contract>({ extensions })`. */
  readonly extensions: ReadonlyArray<SqlRuntimeExtensionDescriptor<'postgres'>>
  /** Ready to spread into `postgres<Contract>({ middleware })`. */
  readonly middleware: ReadonlyArray<SqlMiddleware>
  /**
   * The initialised v3 `TypedEncryptionClient` for direct SDK access
   * outside the ORM path (`encryptModel`, `encryptQuery`, …).
   */
  readonly encryptionClient: TypedEncryptionClient<readonly AnyV3Table[]>
}

export async function cipherstashFromStack(
  opts: CipherstashFromStackV3Options,
): Promise<CipherstashFromStackV3Result> {
  const foreignIds = collectNonV3CipherstashCodecIds(opts.contractJson)
  if (foreignIds.length > 0) {
    throw new Error(
      `cipherstashFromStack: contract.json contains non-v3 cipherstash codec ids [${foreignIds.join(', ')}]. ` +
        'A v3 client is v3-only; use cipherstashFromStackV2 for a v2 contract. ' +
        'Mixed v2+v3 cipherstash columns in one client are unsupported.',
    )
  }

  const derived = deriveStackSchemasV3(opts.contractJson)
  if (derived.length === 0) {
    throw new Error(
      'cipherstashFromStack: no v3 cipherstash columns found in contract.json. ' +
        'Declare at least one v3 `cipherstash.*()` column (e.g. `cipherstash.TextSearch()`) in prisma/schema.prisma ' +
        'and re-emit the contract (or use cipherstashFromStackV2 if this is a v2 contract).',
    )
  }

  const schemas = resolveV3Schemas(derived, opts.schemasV3)

  const encryptionClient = await EncryptionV3({
    schemas,
    ...(opts.encryptionConfig !== undefined
      ? { config: opts.encryptionConfig }
      : {}),
  })

  const sdk = createCipherstashV3Sdk(encryptionClient, schemas)

  return {
    extensions: [createCipherstashV3RuntimeDescriptor({ sdk })],
    middleware: [bulkEncryptMiddlewareV3(sdk)],
    encryptionClient,
  }
}

/**
 * Every `cipherstash/*` codec id in the contract that is NOT a member
 * of the pinned v3 set — i.e. v2 (or unknown-generation) cipherstash
 * columns, which make the contract the wrong input for the v3 entry
 * point.
 */
function collectNonV3CipherstashCodecIds(
  contractJson: V3ContractShape,
): string[] {
  const ids = new Set<string>()
  for (const { codecId } of v3ContractColumnEntries(contractJson)) {
    if (
      typeof codecId === 'string' &&
      codecId.startsWith('cipherstash/') &&
      !isCipherstashV3CodecId(codecId)
    ) {
      ids.add(codecId)
    }
  }
  return [...ids].sort()
}

/**
 * Validate contract-declared tables against their overrides (exact
 * domain identity) and append override-only tables — same merge
 * semantics as the v2 `resolveSchemas`.
 */
function resolveV3Schemas(
  derived: ReadonlyArray<AnyV3Table>,
  override: ReadonlyArray<AnyV3Table> | undefined,
): ReadonlyArray<AnyV3Table> {
  if (override === undefined || override.length === 0) return derived

  const derivedByName = new Map(derived.map((t) => [t.tableName, t]))
  const overrideByName = new Map(override.map((t) => [t.tableName, t]))

  for (const [tableName, derivedTable] of derivedByName) {
    const overrideTable = overrideByName.get(tableName)
    if (overrideTable === undefined) continue
    assertV3SchemasAgree(derivedTable, overrideTable)
  }

  return [
    ...derived,
    ...override.filter((t) => !derivedByName.has(t.tableName)),
  ]
}
