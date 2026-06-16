/**
 * v3 operator lowering — mirrors the v2 operator-lowering harness but builds the
 * `self` as a `cipherstash/string-v3@1` column with `typeParams.index` set, so the
 * operator impls select the v3 dialect (extracted-index-term SQL) and the
 * index/operator mismatch guard is exercised.
 */
import type { PostgresContract } from '@prisma-next/adapter-postgres/types'
import { emptyCodecLookup } from '@prisma-next/framework-components/codec'
import { validateContract } from '@prisma-next/sql-contract/validate'
import {
  type AnyExpression,
  ColumnRef,
  ProjectionItem,
  SelectAst,
  TableSource,
} from '@prisma-next/sql-relational-core/ast'
import { describe, expect, it } from 'vitest'
import { readHandleQueryType } from '../../src/execution/envelope-base'
import type { EncryptedEnvelopeBase } from '../../src/execution/envelope-base'
import { cipherstashQueryOperations, queryTypeForIndex } from '../../src/execution/operators'
import { CIPHERSTASH_STRING_V3_CODEC_ID } from '../../src/extension-metadata/constants'
import type { V3Index } from '../../src/v3/domain-map'
import { makeAdapter } from '../operator-lowering.helpers'

const TABLE = 'user_v3'
const V3_COLUMNS: Record<string, V3Index> = { email: 'equality', bio: 'freeTextSearch', name: 'orderAndRange' }
const DOMAIN: Record<V3Index, string> = {
  equality: 'eql_v3.text_eq',
  freeTextSearch: 'eql_v3.text_match',
  orderAndRange: 'eql_v3.text_ord',
}

const contract = validateContract<PostgresContract>(
  {
    target: 'postgres',
    targetFamily: 'sql',
    profileHash: 'sha256:cipherstash-v3-operator-lowering-test',
    roots: {},
    capabilities: {},
    extensionPacks: {},
    meta: {},
    storage: {
      storageHash: 'sha256:cipherstash-v3-operator-lowering-test-storage',
      tables: {
        [TABLE]: {
          columns: {
            id: { codecId: 'pg/text@1', nativeType: 'text', nullable: false },
            ...Object.fromEntries(
              Object.entries(V3_COLUMNS).map(([col, index]) => [
                col,
                {
                  codecId: CIPHERSTASH_STRING_V3_CODEC_ID,
                  nativeType: DOMAIN[index],
                  typeParams: { index },
                  nullable: true,
                },
              ]),
            ),
          },
          uniques: [],
          indexes: [],
          foreignKeys: [],
        },
      },
    },
    models: {},
  },
  emptyCodecLookup,
)

const ops = cipherstashQueryOperations()

// Column accessor whose CodecRef carries the v3 codec id + typeParams.index, so
// the operator's mismatch guard can read the column's single index.
function v3Column(column: string, index: V3Index) {
  const ref = ColumnRef.of(TABLE, column)
  return {
    returnType: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, nullable: true },
    codec: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: { index } },
    buildAst: () => ref,
  }
}

function predicateAst(method: string, column: string, index: V3Index, ...args: unknown[]): AnyExpression {
  const op = ops[method]
  if (!op) throw new Error(`no operator ${method}`)
  const impl = op.impl as unknown as (...a: unknown[]) => { buildAst(): AnyExpression }
  return impl(v3Column(column, index), ...args).buildAst()
}

function lowerSql(method: string, column: string, index: V3Index, ...args: unknown[]): string {
  const ast = SelectAst.from(TableSource.named(TABLE))
    .withProjection([ProjectionItem.of('id', ColumnRef.of(TABLE, 'id'))])
    .withWhere(predicateAst(method, column, index, ...args))
  return makeAdapter().lower(ast, { contract }).sql
}

describe('v3 operator lowering (cipherstash/string-v3@1)', () => {
  it('cipherstashEq on text_eq → eq_term = hmac_256(arg::jsonb)', () => {
    const sql = lowerSql('cipherstashEq', 'email', 'equality', 'alice')
    expect(sql).toContain('eql_v3.eq_term("user_v3"."email") = eql_v3.hmac_256($1::jsonb')
    // crucial: the param must NOT be coerced into the full-payload domain
    // (eql_v3.text_eq / eql_v3.text), or a search term fails the domain CHECK.
    expect(sql).not.toContain('::eql_v3.text')
  })

  it('cipherstashNe on text_eq → eq_term <> hmac_256', () => {
    const sql = lowerSql('cipherstashNe', 'email', 'equality', 'alice')
    expect(sql).toContain('eql_v3.eq_term("user_v3"."email") <> eql_v3.hmac_256($1::jsonb')
  })

  it('cipherstashLt on text_ord → ord_term < ore_block', () => {
    const sql = lowerSql('cipherstashLt', 'name', 'orderAndRange', 'm')
    expect(sql).toContain('eql_v3.ord_term("user_v3"."name") < eql_v3.ore_block_u64_8_256($1::jsonb')
  })

  it('cipherstashIlike on text_match → match_term @> bloom_filter', () => {
    const sql = lowerSql('cipherstashIlike', 'bio', 'freeTextSearch', '%dev%')
    expect(sql).toContain('eql_v3.match_term("user_v3"."bio") @> eql_v3.bloom_filter($1::jsonb')
  })

  it('cipherstashNotIlike on text_match → NOT (match_term @> bloom_filter)', () => {
    const sql = lowerSql('cipherstashNotIlike', 'bio', 'freeTextSearch', '%dev%')
    expect(sql).toContain('NOT eql_v3.match_term("user_v3"."bio") @> eql_v3.bloom_filter($1::jsonb')
  })

  it('cipherstashBetween on text_ord → ord_term >= … AND ord_term <= …', () => {
    const sql = lowerSql('cipherstashBetween', 'name', 'orderAndRange', 'a', 'z')
    expect(sql).toContain('eql_v3.ord_term("user_v3"."name") >= eql_v3.ore_block_u64_8_256($1::jsonb')
    expect(sql).toContain('AND eql_v3.ord_term("user_v3"."name") <= eql_v3.ore_block_u64_8_256($2::jsonb')
  })

  it('cipherstashInArray on text_eq → OR of eq_term=hmac_256 per element', () => {
    const sql = lowerSql('cipherstashInArray', 'email', 'equality', ['a', 'b'])
    expect(sql).toContain(
      '(eql_v3.eq_term("user_v3"."email") = eql_v3.hmac_256($1::jsonb::jsonb) OR ' +
        'eql_v3.eq_term("user_v3"."email") = eql_v3.hmac_256($2::jsonb::jsonb))',
    )
  })

  it('rejects index/operator mismatch with a clear TypeError', () => {
    // cipherstashGt needs orderAndRange; the email column is text_eq (equality).
    expect(() => lowerSql('cipherstashGt', 'email', 'equality', 'x')).toThrow(/orderAndRange/)
    // cipherstashIlike needs freeTextSearch; email is text_eq.
    expect(() => lowerSql('cipherstashIlike', 'email', 'equality', '%x%')).toThrow(/freeTextSearch/)
  })

  it('stamps the protect queryType on the v3 search-term param', () => {
    const node = predicateAst('cipherstashEq', 'email', 'equality', 'alice') as unknown as {
      args: ReadonlyArray<{ value: unknown }>
    }
    const envelope = node.args[0]?.value as EncryptedEnvelopeBase<unknown>
    expect(readHandleQueryType(envelope)).toBe('equality')
  })

  it('stamps orderAndRange on an ord-column search param', () => {
    const node = predicateAst('cipherstashLt', 'name', 'orderAndRange', 'm') as unknown as {
      args: ReadonlyArray<{ value: unknown }>
    }
    const envelope = node.args[0]?.value as EncryptedEnvelopeBase<unknown>
    expect(readHandleQueryType(envelope)).toBe('orderAndRange')
  })
})

describe('queryTypeForIndex', () => {
  it('maps the column index to the protect query type (identity narrowing)', () => {
    expect(queryTypeForIndex('equality')).toBe('equality')
    expect(queryTypeForIndex('orderAndRange')).toBe('orderAndRange')
    expect(queryTypeForIndex('freeTextSearch')).toBe('freeTextSearch')
  })
})
