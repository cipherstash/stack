/**
 * Shared scaffolding for the `operator-lowering-v3*.test.ts` files —
 * the v3 twin of `../operator-lowering.helpers.ts`.
 *
 * Differences from the v2 helper, both deliberate:
 *
 *   - **Runtime pack**: composes a v3-only extension descriptor built
 *     inline from `createV3CodecDescriptors` + `cipherstashV3QueryOperations`
 *     under v3's OWN extension id (`CIPHERSTASH_V3_SPACE_ID`). Task 7's
 *     `createCipherstashV3RuntimeDescriptor` will productionise this
 *     exact shape; the inline copy keeps the operator tests decoupled
 *     from that task. The v2 descriptor is NEVER co-registered here —
 *     decision 1b (a client is v2 or v3 by construction; the v2
 *     `cipherstash*` and v3 `eql*` method sets are disjoint, pinned in
 *     `operator-gating-v3.test.ts`).
 *   - **Contract columns**: each v3 column carries its concrete
 *     `public.eql_v3_*` domain as `nativeType` plus the
 *     `{ castAs, capabilities }` typeParams block v3 authoring emits —
 *     derived from the catalog so the fixture cannot drift from the
 *     GA domain registry.
 */

import postgresRuntimeAdapter from '@prisma-next/adapter-postgres/runtime'
import type { PostgresContract } from '@prisma-next/adapter-postgres/types'
import type { RuntimeTargetDescriptor } from '@prisma-next/framework-components/execution'
import { validateSqlContractFully } from '@prisma-next/sql-contract/validators'
import type { SqlOperationDescriptor } from '@prisma-next/sql-operations'
import {
  type AnyExpression,
  ColumnRef,
  type LoweredParam,
  type OrderByItem,
  ProjectionItem,
  SelectAst,
  TableSource,
} from '@prisma-next/sql-relational-core/ast'
import {
  createExecutionContext,
  createSqlExecutionStack,
  type SqlRuntimeExtensionDescriptor,
} from '@prisma-next/sql-runtime'
import { vi } from 'vitest'
import type { CipherstashSdk } from '../../src/execution/sdk'
import {
  CIPHERSTASH_V3_EXTENSION_VERSION,
  CIPHERSTASH_V3_SPACE_ID,
} from '../../src/extension-metadata/constants-v3'
import { V3_DOMAIN_META_BY_CODEC_ID } from '../../src/v3/catalog'
import { createV3CodecDescriptors } from '../../src/v3/codec-runtime-v3'
import { cipherstashV3QueryOperations } from '../../src/v3/operators-v3'

// Minimal SDK stub. Operator lowering doesn't talk to the SDK — the codec
// captures it lazily for the read-side decrypt path — but the codec
// descriptors require one.
export function emptySdk(): CipherstashSdk {
  return {
    decrypt: vi.fn(),
    bulkEncrypt: vi.fn(),
    bulkDecrypt: vi.fn(),
  }
}

export const TABLE = 'user'

// GA codec ids (registry key VERBATIM — never strip the `eql_v3_` prefix).
export const TEXT_SEARCH_CODEC_ID = 'cipherstash/eql-v3/eql_v3_text_search@1'
export const TEXT_EQ_CODEC_ID = 'cipherstash/eql-v3/eql_v3_text_eq@1'
export const TEXT_STORAGE_CODEC_ID = 'cipherstash/eql-v3/eql_v3_text@1'
export const INTEGER_ORD_CODEC_ID = 'cipherstash/eql-v3/eql_v3_integer_ord@1'
export const BIGINT_ORD_ORE_CODEC_ID =
  'cipherstash/eql-v3/eql_v3_bigint_ord_ore@1'
export const DATE_ORD_CODEC_ID = 'cipherstash/eql-v3/eql_v3_date_ord@1'
export const BOOLEAN_CODEC_ID = 'cipherstash/eql-v3/eql_v3_boolean@1'
export const JSON_CODEC_ID = 'cipherstash/eql-v3/eql_v3_json_search@1'

/**
 * Build a contract column entry for a v3 codec id, deriving `nativeType`
 * (the concrete `public.eql_v3_*` domain) and the `{ castAs, capabilities }`
 * typeParams block from the catalog so the fixture is always truthful to
 * the GA registry.
 */
function v3Column(codecId: string) {
  const meta = V3_DOMAIN_META_BY_CODEC_ID.get(codecId)
  if (!meta) {
    throw new Error(`operator-lowering-v3 helpers: unknown codec id ${codecId}`)
  }
  return {
    codecId,
    nativeType: meta.nativeType,
    nullable: true,
    typeParams: { castAs: meta.castAs, capabilities: meta.capabilities },
  }
}

export const contractV3 = validateSqlContractFully<PostgresContract>({
  target: 'postgres',
  targetFamily: 'sql',
  profileHash: 'sha256:cipherstash-operator-lowering-v3-test',
  roots: {},
  capabilities: {},
  extensionPacks: {},
  meta: {},
  storage: {
    storageHash: 'sha256:cipherstash-operator-lowering-v3-test-storage',
    namespaces: {
      __unbound__: {
        id: '__unbound__',
        entries: {
          table: {
            [TABLE]: {
              columns: {
                id: {
                  codecId: 'pg/text@1',
                  nativeType: 'text',
                  nullable: false,
                },
                // One column per capability family so every operator can
                // be exercised against a domain that supports it (and a
                // domain that doesn't, for the gating tests).
                email: v3Column(TEXT_SEARCH_CODEC_ID), // match + ope + unique
                nickname: v3Column(TEXT_EQ_CODEC_ID), // unique only
                note: v3Column(TEXT_STORAGE_CODEC_ID), // storage-only
                score: v3Column(INTEGER_ORD_CODEC_ID), // ope (OPE ordering)
                balance: v3Column(BIGINT_ORD_ORE_CODEC_ID), // ore (block-ORE)
                birthday: v3Column(DATE_ORD_CODEC_ID), // ope
                active: v3Column(BOOLEAN_CODEC_ID), // storage-only
                payload: v3Column(JSON_CODEC_ID), // ste_vec
              },
              uniques: [],
              indexes: [],
              foreignKeys: [],
            },
          },
        },
      },
    },
  },
  domain: { namespaces: { __unbound__: { models: {} } } },
})

// Stub runtime target — the Postgres adapter only consults `familyId` /
// `targetId` on the target during `create`. Same inline replica as the
// v2 helper (no postgres-package test-export dependency). The empty
// `codecs` contribution mirrors the real
// `@prisma-next/target-postgres/runtime` descriptor (the target
// contributes no codecs; they ship from the adapter and extension
// packs) and is required by `createExecutionContext`'s contributor
// walk in `assembleV3ExecutionContext`.
const stubRuntimeTarget: RuntimeTargetDescriptor<'sql', 'postgres'> & {
  readonly codecs: () => readonly never[]
} = {
  kind: 'target',
  id: 'postgres',
  version: '0.0.1',
  familyId: 'sql',
  targetId: 'postgres',
  codecs: () => [],
  create() {
    return { familyId: 'sql', targetId: 'postgres' }
  },
}

/**
 * The v3-only runtime extension descriptor — the shape Task 7's
 * `createCipherstashV3RuntimeDescriptor` will export, composed inline
 * so the operator tests don't depend on that task. Registered under
 * v3's own distinct extension id (decision 1b).
 */
export function v3RuntimeDescriptor(
  sdk: CipherstashSdk = emptySdk(),
): SqlRuntimeExtensionDescriptor<'postgres'> {
  const descriptors = createV3CodecDescriptors(sdk)
  return {
    kind: 'extension' as const,
    id: CIPHERSTASH_V3_SPACE_ID,
    version: CIPHERSTASH_V3_EXTENSION_VERSION,
    familyId: 'sql' as const,
    targetId: 'postgres' as const,
    types: { codecTypes: { codecDescriptors: descriptors } },
    codecs: () => descriptors,
    queryOperations: () => cipherstashV3QueryOperations(),
    create() {
      return { familyId: 'sql' as const, targetId: 'postgres' as const }
    },
  }
}

export function makeV3Adapter(
  extensionPacks: ReadonlyArray<SqlRuntimeExtensionDescriptor<'postgres'>> = [
    v3RuntimeDescriptor(),
  ],
) {
  return postgresRuntimeAdapter.create({
    target: stubRuntimeTarget,
    adapter: postgresRuntimeAdapter,
    driver: undefined,
    extensionPacks: [...extensionPacks],
  })
}

/**
 * Assemble a full SQL execution context (contract + stack) — the step
 * that builds the flat `OperationRegistry` from every contributor's
 * `queryOperations()`. This is where a duplicate method name across
 * extension packs would throw (`adapter.lower` alone never touches the
 * registry), so the decision-1b registration pins drive this path.
 */
export function assembleV3ExecutionContext(
  extensionPacks: ReadonlyArray<SqlRuntimeExtensionDescriptor<'postgres'>> = [
    v3RuntimeDescriptor(),
  ],
) {
  return createExecutionContext({
    contract: contractV3,
    stack: createSqlExecutionStack({
      target: stubRuntimeTarget,
      adapter: postgresRuntimeAdapter,
      extensionPacks: [...extensionPacks],
    }),
  })
}

const cipherstashV3OperatorsByMethod = cipherstashV3QueryOperations()

export function getOperator(method: string): SqlOperationDescriptor {
  const op = cipherstashV3OperatorsByMethod[method]
  if (!op) {
    throw new Error(
      `cipherstash v3 operator descriptor for method "${method}" not found`,
    )
  }
  return op
}

/**
 * Invoke an operator's `impl` and return the produced AST node. Same
 * cast rationale as the v2 helper: `op.impl` is typed
 * `(...args: never[]) => QueryOperationReturn` to block accidental
 * direct invocation; the practical shape is
 * `(self, ...args) => Expression<...>`.
 */
export function callOperator(
  op: SqlOperationDescriptor,
  ...args: unknown[]
): AnyExpression {
  const impl = op.impl as unknown as (...args: unknown[]) => {
    buildAst(): AnyExpression
  }
  return impl(...args).buildAst()
}

/**
 * Build the same `Expression`-like shape the ORM model accessor
 * synthesises for a column field: `buildAst()` returning the underlying
 * `ColumnRef` plus the column's return-type metadata carrying the v3
 * codec id.
 */
export function columnAccessorV3(
  table: string,
  column: string,
  codecId: string,
) {
  const ref = ColumnRef.of(table, column)
  return {
    returnType: { codecId, nullable: true },
    buildAst: () => ref,
  }
}

export function selectWithWhere(whereExpr: AnyExpression) {
  return SelectAst.from(TableSource.named(TABLE))
    .withProjection([ProjectionItem.of('id', ColumnRef.of(TABLE, 'id'))])
    .withWhere(whereExpr)
}

export function selectWithOrderBy(items: ReadonlyArray<OrderByItem>) {
  return SelectAst.from(TableSource.named(TABLE))
    .withProjection([ProjectionItem.of('id', ColumnRef.of(TABLE, 'id'))])
    .withOrderBy(items)
}

/**
 * Unwrap the value carried by a lowered `literal` param (structured
 * `LoweredParam` entries since 0.9 — same helper as the v2 file).
 */
export function literalParamValue(param: LoweredParam): unknown {
  if (param.kind !== 'literal') {
    throw new Error(
      `expected a literal lowered param, got kind '${param.kind}'`,
    )
  }
  return param.value
}
