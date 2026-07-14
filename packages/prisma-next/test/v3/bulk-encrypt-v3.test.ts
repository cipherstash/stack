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
  InsertAst,
  ParamRef,
  TableSource,
} from '@prisma-next/sql-relational-core/ast'
import type { SqlExecutionPlan } from '@prisma-next/sql-relational-core/plan'
import { describe, expect, it } from 'vitest'
import { EncryptedJson } from '../../src/execution/envelope-json'
import { EncryptedString } from '../../src/execution/envelope-string'
import { CIPHERSTASH_STRING_CODEC_ID } from '../../src/extension-metadata/constants'
import { isCipherstashV3CodecId } from '../../src/extension-metadata/constants-v3'
import { bulkEncryptMiddlewareV3 } from '../../src/v3/bulk-encrypt-v3'
import {
  baseMeta,
  buildInsertPlan,
  buildUpdatePlan,
  createCtx,
  createSqlParamRefMutator,
  makeCounterSdk,
} from '../bulk-encrypt-middleware.helpers'

const V3_TEXT_SEARCH = 'cipherstash/eql-v3/eql_v3_text_search@1'
const V3_JSON = 'cipherstash/eql-v3/eql_v3_json@1'

it('test fixture codec ids are members of the pinned v3 set', () => {
  expect(isCipherstashV3CodecId(V3_TEXT_SEARCH)).toBe(true)
  expect(isCipherstashV3CodecId(V3_JSON)).toBe(true)
  expect(isCipherstashV3CodecId(CIPHERSTASH_STRING_CODEC_ID)).toBe(false)
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

  describe('jurisdiction is the v3 codec-id set only', () => {
    it('ignores v2-codec params', async () => {
      const sdk = makeV3Sdk()
      const middleware = bulkEncryptMiddlewareV3(sdk)
      const plan = buildInsertPlan(
        'user',
        [{ email: EncryptedString.from('x') }],
        CIPHERSTASH_STRING_CODEC_ID,
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

      await expect(
        middleware.beforeExecute?.(
          plan,
          createCtx({ signal: controller.signal }),
          params,
        ),
      ).rejects.toThrow()
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
