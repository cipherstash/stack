/**
 * v3 operator capability gating + registration constraints.
 *
 * Every v3 operator gates on the CONCRETE domain's query capabilities
 * (derived from the catalog by codec id) before building any AST, and
 * throws `EncryptionOperatorError` naming the column, domain, operator,
 * and missing capability. Trait dispatch alone is not enough: traits
 * are per-codec, and a caller reaching the operator descriptor directly
 * (or through a custom builder) must still be stopped when the domain
 * cannot answer the operator.
 *
 * Also pins decision 1b's registration constraint: the v3 descriptor
 * stands alone (a v3-only adapter builds cleanly), and co-registering
 * the v2 and v3 descriptors throws — the framework's flat
 * `OperationRegistry` rejects two descriptors sharing the
 * `cipherstashEq` method name. v2 and v3 are separate entry points,
 * never composed into one client.
 */

import { describe, expect, it } from 'vitest'
import { createCipherstashRuntimeDescriptor } from '../../src/exports/runtime'
import {
  cipherstashV3Asc,
  cipherstashV3QueryOperations,
  EncryptionOperatorError,
} from '../../src/v3/operators-v3'
import {
  assembleV3ExecutionContext,
  BOOLEAN_CODEC_ID,
  callOperator,
  columnAccessorV3,
  emptySdk,
  getOperator,
  JSON_CODEC_ID,
  makeV3Adapter,
  TABLE,
  TEXT_EQ_CODEC_ID,
  TEXT_STORAGE_CODEC_ID,
  v3RuntimeDescriptor,
} from './operator-lowering-v3.helpers'

describe('v3 operator capability gating', () => {
  it('equality requires the equality capability — storage-only eql_v3_text rejects cipherstashEq', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashEq'),
        columnAccessorV3(TABLE, 'note', TEXT_STORAGE_CODEC_ID),
        'x',
      ),
    ).toThrow(EncryptionOperatorError)
  })

  it('names the column, domain, operator, and missing capability in the diagnostic', () => {
    try {
      callOperator(
        getOperator('cipherstashEq'),
        columnAccessorV3(TABLE, 'note', TEXT_STORAGE_CODEC_ID),
        'x',
      )
      expect.unreachable('cipherstashEq on a storage-only column must throw')
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionOperatorError)
      const operatorError = error as EncryptionOperatorError
      expect(operatorError.message).toContain('cipherstashEq')
      expect(operatorError.message).toContain('equality')
      expect(operatorError.message).toContain('"note"')
      expect(operatorError.message).toContain('public.eql_v3_text')
      expect(operatorError.context).toEqual({
        columnName: 'note',
        tableName: TABLE,
        operator: 'cipherstashEq',
      })
    }
  })

  it('comparison requires order/range — text_eq rejects cipherstashGt', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashGt'),
        columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
        'x',
      ),
    ).toThrow(/order\/range/)
  })

  it('free-text requires the match index — text_eq rejects cipherstashIlike', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashIlike'),
        columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
        'x',
      ),
    ).toThrow(/free-text/)
  })

  it('JSON containment requires searchableJson — text_eq rejects cipherstashJsonContains', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashJsonContains'),
        columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
        { role: 'admin' },
      ),
    ).toThrow(/JSON containment/)
  })

  it('eql_v3_json is searchableJson-only — rejects cipherstashEq', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashEq'),
        columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
        { role: 'admin' },
      ),
    ).toThrow(/equality/)
  })

  it('storage-only eql_v3_boolean rejects every search operator', () => {
    for (const method of [
      'cipherstashEq',
      'cipherstashNe',
      'cipherstashGt',
      'cipherstashIlike',
      'cipherstashJsonContains',
    ]) {
      expect(() =>
        callOperator(
          getOperator(method),
          columnAccessorV3(TABLE, 'active', BOOLEAN_CODEC_ID),
          true,
        ),
      ).toThrow(EncryptionOperatorError)
    }
  })

  it('ordering helpers gate on order/range — text_eq rejects cipherstashV3Asc', () => {
    expect(() =>
      cipherstashV3Asc(columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID)),
    ).toThrow(/order\/range/)
  })

  it('rejects a non-v3 codec id (v2 columns are the wrong entry point)', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashEq'),
        columnAccessorV3(TABLE, 'email', 'cipherstash/string@1'),
        'x',
      ),
    ).toThrow(/not a .*v3 domain/)
  })

  it('rejects a self expression with no codec binding', () => {
    expect(() =>
      callOperator(
        getOperator('cipherstashEq'),
        {
          buildAst: () => {
            throw new Error('unreachable')
          },
        },
        'x',
      ),
    ).toThrow(/missing a CodecRef/)
  })
})

describe('v3 descriptor registration (decision 1b)', () => {
  it('a v3-only adapter builds and registers its operation set cleanly', () => {
    expect(() => makeV3Adapter()).not.toThrow()
    // The execution context is what assembles the flat operation
    // registry from `queryOperations()` — a v3-only stack registers the
    // full `cipherstash*` method set without collision.
    const registered = Object.keys(
      assembleV3ExecutionContext().queryOperations.entries(),
    )
    expect(registered).toEqual(
      expect.arrayContaining([...Object.keys(cipherstashV3QueryOperations())]),
    )
  })

  it('co-registering the v2 and v3 descriptors throws on the shared method names', () => {
    // Both descriptors define `cipherstashEq` (and eleven siblings); the
    // flat, method-keyed OperationRegistry disallows override. This is
    // WHY v2 and v3 are separate entry points that are never composed
    // into one client. The registry is assembled when the execution
    // context is built against a contract, so the collision surfaces
    // there rather than at adapter construction.
    expect(() =>
      assembleV3ExecutionContext([
        createCipherstashRuntimeDescriptor({ sdk: emptySdk() }),
        v3RuntimeDescriptor(),
      ]),
    ).toThrow(/already registered/)
  })
})
