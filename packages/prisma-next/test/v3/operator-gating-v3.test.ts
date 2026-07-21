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
 * Also pins decision 1b's registration posture: the v3 descriptor
 * stands alone (a v3-only adapter builds cleanly) and registers its
 * full method set without collision, every method wearing the `eql*`
 * prefix. A contract carrying a v2 cipherstash codec id is rejected
 * outright — v2 is no longer a surface this package serves.
 */

import { describe, expect, it } from 'vitest'
import {
  cipherstashV3QueryOperations,
  EncryptionOperatorError,
  eqlAsc,
} from '../../src/v3/operators-v3'
import {
  assembleV3ExecutionContext,
  BOOLEAN_CODEC_ID,
  callOperator,
  columnAccessorV3,
  getOperator,
  JSON_CODEC_ID,
  makeV3Adapter,
  TABLE,
  TEXT_EQ_CODEC_ID,
  TEXT_STORAGE_CODEC_ID,
} from './operator-lowering-v3.helpers'

describe('v3 operator capability gating', () => {
  it('equality requires the equality capability — storage-only eql_v3_text rejects eqlEq', () => {
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'note', TEXT_STORAGE_CODEC_ID),
        'x',
      ),
    ).toThrow(EncryptionOperatorError)
  })

  it('names the column, domain, operator, and missing capability in the diagnostic', () => {
    try {
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'note', TEXT_STORAGE_CODEC_ID),
        'x',
      )
      expect.unreachable('eqlEq on a storage-only column must throw')
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionOperatorError)
      const operatorError = error as EncryptionOperatorError
      expect(operatorError.message).toContain('eqlEq')
      expect(operatorError.message).toContain('equality')
      expect(operatorError.message).toContain('"note"')
      expect(operatorError.message).toContain('public.eql_v3_text')
      expect(operatorError.context).toEqual({
        columnName: 'note',
        tableName: TABLE,
        operator: 'eqlEq',
      })
    }
  })

  it('comparison requires order/range — text_eq rejects eqlGt', () => {
    expect(() =>
      callOperator(
        getOperator('eqlGt'),
        columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
        'x',
      ),
    ).toThrow(/order\/range/)
  })

  it('free-text requires the match index — text_eq rejects eqlMatch', () => {
    expect(() =>
      callOperator(
        getOperator('eqlMatch'),
        columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
        'x',
      ),
    ).toThrow(/free-text/)
  })

  it('JSON containment requires searchableJson — text_eq rejects eqlJsonContains', () => {
    expect(() =>
      callOperator(
        getOperator('eqlJsonContains'),
        columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID),
        { role: 'admin' },
      ),
    ).toThrow(/JSON containment/)
  })

  it('eql_v3_json is searchableJson-only — rejects eqlEq', () => {
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'payload', JSON_CODEC_ID),
        { role: 'admin' },
      ),
    ).toThrow(/equality/)
  })

  it('storage-only eql_v3_boolean rejects every search operator', () => {
    for (const method of [
      'eqlEq',
      'eqlNeq',
      'eqlGt',
      'eqlMatch',
      'eqlJsonContains',
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

  it('ordering helpers gate on order/range — text_eq rejects eqlAsc', () => {
    expect(() =>
      eqlAsc(columnAccessorV3(TABLE, 'nickname', TEXT_EQ_CODEC_ID)),
    ).toThrow(/order\/range/)
  })

  it('rejects a non-v3 codec id (v2 columns are the wrong entry point)', () => {
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
        columnAccessorV3(TABLE, 'email', 'cipherstash/string@1'),
        'x',
      ),
    ).toThrow(/not a .*v3 domain/)
  })

  it('rejects a self expression with no codec binding', () => {
    expect(() =>
      callOperator(
        getOperator('eqlEq'),
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
    // full `eql*` method set without collision.
    const registered = Object.keys(
      assembleV3ExecutionContext().queryOperations.entries(),
    )
    expect(registered).toEqual(
      expect.arrayContaining([...Object.keys(cipherstashV3QueryOperations())]),
    )
  })

  it('every v3 operator method wears the `eql` prefix', () => {
    // The v3 registry speaks the EQL-derived `eql*` vocabulary
    // (PR #655 review): a fixed, self-consistent naming surface on the
    // flat method-keyed OperationRegistry. Generation identity is fixed
    // at client construction (decision 1b), not resolved per method
    // name.
    const v3Methods = Object.keys(cipherstashV3QueryOperations())
    expect(v3Methods.length).toBeGreaterThan(0)
    expect(v3Methods.every((method) => method.startsWith('eql'))).toBe(true)
  })
})
