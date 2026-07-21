/**
 * v3 bulk-encrypt middleware behaviour.
 *
 * Mirrors the v2 suite's contract (`../bulk-encrypt-middleware.test.ts`)
 * via the shared harness, with the two v3-specific deltas under test:
 *
 *   - **Jurisdiction** is the v3 codec-id set only: v2-codec'd params
 *     (and non-cipherstash params) are invisible to this middleware.
 *   - **Wire** is plain JSONB text (`v3ToDriver` of the EQL payload) —
 *     never the v2 `eql_v2_encrypted` composite literal (`("...")`).
 *
 * The mock SDK returns object EQL payloads (`{ c: ... }`) so the tests
 * observe the JSON.stringify boundary the pg driver will see.
 */

import {
  ColumnRef,
  InsertAst,
  ParamRef,
  ProjectionItem,
  SelectAst,
  TableSource,
} from '@prisma-next/sql-relational-core/ast'
import type { SqlExecutionPlan } from '@prisma-next/sql-relational-core/plan'
import { describe, expect, it } from 'vitest'
import type { EncryptedEnvelopeBase } from '../../src/execution/envelope-base'
import { setHandleRoutingKey } from '../../src/execution/envelope-base'
import { EncryptedJson } from '../../src/execution/envelope-json'
import { EncryptedString } from '../../src/execution/envelope-string'

// A non-v3 codec id — used to prove the guard and the v3 middleware reject
// anything outside the pinned v3 set. (The legacy EQL v2 codec ids were
// removed; this literal stands in for "not a v3 codec id".)
const NON_V3_CODEC_ID = 'cipherstash/string@1'

import { isCipherstashV3CodecId } from '../../src/extension-metadata/constants-v3'
import { bulkEncryptMiddlewareV3 } from '../../src/v3/bulk-encrypt-v3'
import { EncryptedNumber } from '../../src/v3/envelope-number'
import { markV3QueryTerm } from '../../src/v3/query-term'
import { v3ToDriver } from '../../src/v3/wire-v3'
import {
  baseMeta,
  buildInsertPlan,
  buildUpdatePlan,
  createCtx,
  createSqlParamRefMutator,
  makeCounterSdk,
} from '../bulk-encrypt-middleware.helpers'
import {
  callOperator,
  columnAccessorV3,
  contractV3,
  getOperator,
  INTEGER_ORD_CODEC_ID,
  literalParamValue,
  makeV3Adapter,
  selectWithWhere,
  TABLE,
} from './operator-lowering-v3.helpers'

const V3_TEXT_SEARCH = 'cipherstash/eql-v3/eql_v3_text_search@1'
const V3_JSON = 'cipherstash/eql-v3/eql_v3_json_search@1'

it('test fixture codec ids are members of the pinned v3 set', () => {
  expect(isCipherstashV3CodecId(V3_TEXT_SEARCH)).toBe(true)
  expect(isCipherstashV3CodecId(V3_JSON)).toBe(true)
  expect(isCipherstashV3CodecId(NON_V3_CODEC_ID)).toBe(false)
})

/** SDK whose ciphertexts are object EQL payloads, the v3 SDK shape. */
function makeV3Sdk() {
  return makeCounterSdk({
    encryptImpl: (args) =>
      args.values.map((plaintext) => ({ c: `enc:${String(plaintext)}` })),
  })
}

describe('bulkEncryptMiddlewareV3', () => {
  describe('identity', () => {
    it('declares the SQL family + the v3 middleware name', () => {
      const middleware = bulkEncryptMiddlewareV3(makeV3Sdk())
      expect(middleware.familyId).toBe('sql')
      expect(middleware.name).toBe('cipherstash.bulk-encrypt-v3')
    })
  })

  describe('param slot carries plain JSONB text post-middleware', () => {
    it('bulk-encrypts v3 params and writes plain JSONB (never the v2 composite)', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedString.from('alice@example.com')
      const plan = buildInsertPlan(
        'user',
        [{ email: envelope }],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.routingKey).toEqual({
        table: 'user',
        column: 'email',
      })
      const finalParams = params.currentParams()
      expect(finalParams).toHaveLength(1)
      const onlyParam = finalParams[0]
      expect(onlyParam).toBe('{"c":"enc:alice@example.com"}')
      // Never the v2 `eql_v2_encrypted` composite literal.
      expect(onlyParam).not.toMatch(/^\(/)
    })

    it('round-trips a json castAs envelope (EncryptedJson) like the others', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plaintext = { role: 'admin', tags: ['a', 'b'] }
      const envelope = EncryptedJson.from(plaintext)
      const plan = buildInsertPlan('doc', [{ payload: envelope }], V3_JSON)
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      // The SDK sees the original JS object plaintext untouched.
      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.values).toEqual([plaintext])
      // The param slot carries the serialised EQL payload; the handle
      // keeps both slots for follow-on reuse.
      expect(params.currentParams()[0]).toBe('{"c":"enc:[object Object]"}')
      expect(envelope.expose().ciphertext).toEqual({
        c: 'enc:[object Object]',
      })
      expect(envelope.expose().plaintext).toEqual(plaintext)
      await expect(envelope.decrypt()).resolves.toEqual(plaintext)
      expect(sdk.singleDecryptCalls).toEqual([])
    })
  })

  describe('one bulkEncrypt call per (table, column) group', () => {
    it('collapses N rows in one column into a single SDK round-trip', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelopes = Array.from({ length: 10 }, (_, i) =>
        EncryptedString.from(`alice${i}@example.com`),
      )
      const plan = buildInsertPlan(
        'user',
        envelopes.map((e) => ({ email: e })),
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.values).toEqual(
        envelopes.map((_, i) => `alice${i}@example.com`),
      )
      expect(params.currentParams()).toEqual(
        envelopes.map((_, i) => `{"c":"enc:alice${i}@example.com"}`),
      )
    })

    it('partitions targets across (table, column) groups', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildInsertPlan(
        'user',
        [
          {
            email: EncryptedString.from('a@x.com'),
            username: EncryptedString.from('alice'),
          },
          {
            email: EncryptedString.from('b@x.com'),
            username: EncryptedString.from('bob'),
          },
        ],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toHaveLength(2)
      const byColumn = new Map(
        sdk.bulkEncryptCalls.map((c) => [c.routingKey.column, c]),
      )
      expect(byColumn.get('email')?.values).toEqual(['a@x.com', 'b@x.com'])
      expect(byColumn.get('username')?.values).toEqual(['alice', 'bob'])
    })

    it('stamps (table, column) from UpdateAst before grouping', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildUpdatePlan(
        'admin',
        { email: EncryptedString.from('alice@example.com') },
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.routingKey).toEqual({
        table: 'admin',
        column: 'email',
      })
      expect(params.currentParams()[0]).toBe('{"c":"enc:alice@example.com"}')
    })
  })

  describe('routing key write-once contract', () => {
    it('rejects one envelope instance reused across two different columns', async () => {
      // Same programming-error pin as the v2 suite
      // (`../bulk-encrypt-middleware.test.ts`), through the v3 path:
      // `stampRoutingKeysFromAst` stamps the first column, then
      // `setHandleRoutingKey` throws on the conflicting reassignment so
      // the envelope cannot silently retain a stale binding and route
      // to the wrong bulk-encrypt batch.
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedString.from('alice@example.com')
      const plan = buildInsertPlan(
        'user',
        [{ email: envelope, username: envelope }],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await expect(
        middleware.beforeExecute?.(plan, createCtx(), params),
      ).rejects.toThrow(/routing-key (table|column) conflict/)
      expect(sdk.bulkEncryptCalls).toEqual([])
    })
  })

  describe('jurisdiction is the v3 codec-id set only', () => {
    it('ignores non-v3-codec params', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildInsertPlan(
        'user',
        [{ email: EncryptedString.from('x') }],
        NON_V3_CODEC_ID,
      )
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toEqual([])
    })

    it('ignores non-cipherstash codec ids and uncodec’d params', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const ast = new InsertAst(TableSource.named('user'), [
        {
          id: ParamRef.of(1, { codec: { codecId: 'pg/text@1' } }),
          name: ParamRef.of('plain'),
        },
      ])
      const plan = {
        sql: 'INSERT INTO "user" (id, name) VALUES ($1, $2)',
        params: [1, 'plain'],
        meta: { ...baseMeta },
        ast,
      } as SqlExecutionPlan
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toEqual([])
    })
  })

  describe('ctx.signal is forwarded by identity to the SDK', () => {
    it('passes ctx.signal to bulkEncrypt by reference', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildInsertPlan(
        'user',
        [{ email: EncryptedString.from('alice@example.com') }],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)
      const controller = new AbortController()

      await middleware.beforeExecute?.(
        plan,
        createCtx({ signal: controller.signal }),
        params,
      )

      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.signal).toBe(controller.signal)
    })

    it('omits signal when ctx.signal is undefined', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildInsertPlan(
        'user',
        [{ email: EncryptedString.from('alice@example.com') }],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.signal).toBeUndefined()
    })

    it('short-circuits with RUNTIME.ABORTED before any SDK call when already aborted', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildInsertPlan(
        'user',
        [{ email: EncryptedString.from('alice@example.com') }],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)
      const controller = new AbortController()
      controller.abort()

      // The rejection is the cipherstash-tagged `RUNTIME.ABORTED`
      // envelope (`checkCipherstashAborted(ctx.signal, 'bulk-encrypt')`
      // in `src/execution/abort.ts`), not just any error.
      await expect(
        middleware.beforeExecute?.(
          plan,
          createCtx({ signal: controller.signal }),
          params,
        ),
      ).rejects.toMatchObject({
        code: 'RUNTIME.ABORTED',
        message: 'Operation aborted during bulk-encrypt',
        details: { phase: 'bulk-encrypt' },
      })
      expect(sdk.bulkEncryptCalls).toEqual([])
    })
  })

  describe('plaintext slot is retained post-encrypt', () => {
    it('decrypt() returns plaintext synchronously without consulting the SDK', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedString.from('alice@example.com')
      const plan = buildInsertPlan(
        'user',
        [{ email: envelope }],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(envelope.expose().plaintext).toBe('alice@example.com')
      await expect(envelope.decrypt()).resolves.toBe('alice@example.com')
      expect(sdk.singleDecryptCalls).toEqual([])
      expect(sdk.bulkDecryptCalls).toEqual([])
    })
  })

  describe('query-term params (Task 6 → Task 7 seam)', () => {
    /**
     * Build a plan carrying one query-term param: an envelope MARKED by
     * `markV3QueryTerm` (what the v3 operators do at lowering time),
     * routing pre-stamped, bound under the bare-rendering `pg/text@1`
     * codec (never a v3 codec id).
     */
    function queryTermPlan(
      envelope: EncryptedEnvelopeBase<unknown>,
      column = 'email',
    ): SqlExecutionPlan {
      const ref = ParamRef.of(envelope, { codec: { codecId: 'pg/text@1' } })
      // A WHERE-operand param lives outside insert/update rows; the AST
      // shape here only needs to expose the ParamRef to the mutator.
      const ast = new InsertAst(TableSource.named('user'), [{ [column]: ref }])
      return {
        sql: 'SELECT ... WHERE eql_v3.eq("user"."email", $1::eql_v3.query_text_search)',
        params: [envelope],
        meta: { ...baseMeta },
        ast,
      } as SqlExecutionPlan
    }

    it('forwards the MARKED ENVELOPE itself through sdk.bulkEncrypt and writes the term back as JSONB text', async () => {
      const term = { i: { t: 'user', c: 'email' }, hm: 'term' }
      const sdk = makeCounterSdk({ encryptImpl: () => [term] })
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedString.from('alice@example.com')
      setHandleRoutingKey(envelope, 'user', 'email')
      markV3QueryTerm(envelope, 'equality')
      const plan = queryTermPlan(envelope)
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.routingKey).toEqual({
        table: 'user',
        column: 'email',
      })
      // The envelope travels the seam by IDENTITY, mark intact — the v3
      // SDK adapter reads it to route through encryptQuery.
      expect(sdk.bulkEncryptCalls[0]?.values).toEqual([envelope])
      expect(params.currentParams()[0]).toBe(v3ToDriver(term))
    })

    it('does NOT stamp the query term into the envelope ciphertext slot', async () => {
      const sdk = makeCounterSdk({ encryptImpl: () => [{ hm: 'term' }] })
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedString.from('alice@example.com')
      setHandleRoutingKey(envelope, 'user', 'email')
      markV3QueryTerm(envelope, 'freeTextSearch')
      const plan = queryTermPlan(envelope)
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(envelope.expose().ciphertext).toBeUndefined()
      expect(envelope.expose().plaintext).toBe('alice@example.com')
    })

    it('writes steVecSelector as bare SQL text, not a quoted JSON string', async () => {
      const selectorHash = 'selector-hash'
      const sdk = makeCounterSdk({ encryptImpl: () => [selectorHash] })
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedJson.from('$.profile.age')
      setHandleRoutingKey(envelope, 'user', 'payload')
      markV3QueryTerm(envelope, 'steVecSelector')
      const plan = queryTermPlan(envelope, 'payload')
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(params.currentParams()[0]).toBe(selectorHash)
      expect(params.currentParams()[0]).not.toBe(v3ToDriver(selectorHash))
    })

    it('rejects a non-string steVecSelector result', async () => {
      const sdk = makeCounterSdk({ encryptImpl: () => [{ bad: 'selector' }] })
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedJson.from('$.profile.age')
      setHandleRoutingKey(envelope, 'user', 'payload')
      markV3QueryTerm(envelope, 'steVecSelector')
      const plan = queryTermPlan(envelope, 'payload')
      const params = createSqlParamRefMutator(plan)

      await expect(
        middleware.beforeExecute?.(plan, createCtx(), params),
      ).rejects.toThrow(/steVecSelector must resolve to a bare string hash/)
    })

    it('groups a storage value and a query term on the same column into one SDK call, position-stable', async () => {
      const sdk = makeCounterSdk({
        encryptImpl: (args) =>
          args.values.map((value) =>
            value instanceof EncryptedString
              ? { term: value.expose().plaintext }
              : { c: `enc:${String(value)}` },
          ),
      })
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const storageEnvelope = EncryptedString.from('new@example.com')
      const termEnvelope = EncryptedString.from('old@example.com')
      setHandleRoutingKey(termEnvelope, 'user', 'email')
      markV3QueryTerm(termEnvelope, 'equality')

      // UPDATE user SET email = $1(storage) WHERE email = $2(term)
      const storageRef = ParamRef.of(storageEnvelope, {
        codec: { codecId: V3_TEXT_SEARCH },
      })
      const termRef = ParamRef.of(termEnvelope, {
        codec: { codecId: 'pg/text@1' },
      })
      const ast = new InsertAst(TableSource.named('user'), [
        { email: storageRef },
        { email: termRef },
      ])
      const plan = {
        sql: 'UPDATE ...',
        params: [storageEnvelope, termEnvelope],
        meta: { ...baseMeta },
        ast,
      } as SqlExecutionPlan
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      // AST param order: the SET storage value first, the WHERE term
      // second — the storage value travels as raw plaintext, the query
      // term as the marked envelope itself.
      expect(sdk.bulkEncryptCalls[0]?.values).toEqual([
        'new@example.com',
        termEnvelope,
      ])
      expect(params.currentParams()).toEqual([
        v3ToDriver({ c: 'enc:new@example.com' }),
        v3ToDriver({ term: 'old@example.com' }),
      ])
      // Storage envelope caches its ciphertext; the term envelope does not.
      expect(storageEnvelope.expose().ciphertext).toEqual({
        c: 'enc:new@example.com',
      })
      expect(termEnvelope.expose().ciphertext).toBeUndefined()
    })

    it('throws when a marked envelope has no routing context', async () => {
      const sdk = makeCounterSdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedString.from('alice@example.com')
      markV3QueryTerm(envelope, 'equality')
      // A WHERE-side param on a SELECT: the insert/update AST walk has
      // nothing to stamp from and no operator stamped routing.
      const ref = ParamRef.of(envelope, { codec: { codecId: 'pg/text@1' } })
      const ast = SelectAst.from(TableSource.named('user'))
        .withProjection([ProjectionItem.of('id', ColumnRef.of('user', 'id'))])
        .withWhere(ref)
      const plan = {
        sql: 'SELECT "user"."id" FROM "user" WHERE $1',
        params: [envelope],
        meta: { ...baseMeta },
        ast,
      } as SqlExecutionPlan
      const params = createSqlParamRefMutator(plan)

      await expect(
        middleware.beforeExecute?.(plan, createCtx(), params),
      ).rejects.toThrow(/without a[\s\S]*routing context/)
      expect(sdk.bulkEncryptCalls).toEqual([])
    })

    it('END-TO-END: a real eqlEq lowering feeds the seam and the param lands as query-term JSONB', async () => {
      const term = { i: { t: TABLE, c: 'score' }, ob: ['deadbeef'] }
      const sdk = makeCounterSdk({ encryptImpl: () => [term] })
      const middleware = bulkEncryptMiddlewareV3(sdk)

      const predicate = callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'score', INTEGER_ORD_CODEC_ID),
        42,
      )
      const ast = selectWithWhere(predicate)
      const lowered = makeV3Adapter().lower(ast, { contract: contractV3 })
      const plan = {
        sql: lowered.sql,
        params: lowered.params.map(literalParamValue),
        meta: { ...baseMeta },
        ast,
      } as SqlExecutionPlan
      const params = createSqlParamRefMutator(plan)

      await middleware.beforeExecute?.(plan, createCtx(), params)

      // The operator minted a marked envelope; the middleware forwarded
      // it by identity under the (user, score) routing key…
      expect(sdk.bulkEncryptCalls).toHaveLength(1)
      expect(sdk.bulkEncryptCalls[0]?.routingKey).toEqual({
        table: TABLE,
        column: 'score',
      })
      const forwarded = sdk.bulkEncryptCalls[0]?.values[0]
      expect(forwarded).toBeInstanceOf(EncryptedNumber)
      // …and wrote the resulting term back as the JSONB text the
      // `$1::eql_v3.query_integer_ord` template consumes.
      expect(lowered.sql).toContain('::eql_v3.query_integer_ord')
      expect(params.currentParams()[0]).toBe(v3ToDriver(term))
    })
  })

  describe('no-op cases', () => {
    it('skips when params is undefined', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = {
        sql: 'SELECT 1',
        params: [],
        meta: { ...baseMeta },
      } as unknown as SqlExecutionPlan

      await middleware.beforeExecute?.(plan, createCtx())

      expect(sdk.bulkEncryptCalls).toEqual([])
    })
  })

  describe('error paths', () => {
    it('throws when the SDK returns the wrong number of ciphertexts', async () => {
      const sdk = makeCounterSdk({ encryptImpl: () => [{ c: 'only-one' }] })
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildInsertPlan(
        'user',
        [
          { email: EncryptedString.from('a@x') },
          { email: EncryptedString.from('b@y') },
        ],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await expect(
        middleware.beforeExecute?.(plan, createCtx(), params),
      ).rejects.toThrow(/1 ciphertexts.*2 were requested/)
    })

    it('throws on a v3-codec envelope with no plaintext', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const envelope = EncryptedString.fromInternal({
        ciphertext: { c: 'pre-existing' },
        table: 'user',
        column: 'email',
        sdk,
      })
      const plan = buildInsertPlan(
        'user',
        [{ email: envelope }],
        V3_TEXT_SEARCH,
      )
      const params = createSqlParamRefMutator(plan)

      await expect(
        middleware.beforeExecute?.(plan, createCtx(), params),
      ).rejects.toThrow(/no plaintext/)
      expect(sdk.bulkEncryptCalls).toEqual([])
    })
  })
})
