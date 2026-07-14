import {
  encryptedType,
  ProtectConfigError,
  ProtectOperatorError,
} from '@cipherstash/drizzle/pg'
import type { SQL } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { setup } from './test-utils'

// ============================================================================
// Test table definitions
// ============================================================================

const usersTable = pgTable('users', {
  email: encryptedType<string>('email', {
    equality: true,
    freeTextSearch: true,
    orderAndRange: true,
  }),
  age: encryptedType<number>('age', {
    dataType: 'number',
    orderAndRange: true,
  }),
  name: encryptedType<string>('name', {
    equality: true,
  }),
  bio: encryptedType<string>('bio', {
    freeTextSearch: true,
  }),
})

// ============================================================================
// 2a. Comparison operators
// ============================================================================

describe('Comparison operators', () => {
  it('eq on column with equality config uses = with encrypted param', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.eq(usersTable.name, 'Alice')
    const query = dialect.sqlToQuery(condition)

    // eq with equality config uses regular Drizzle eq (= operator)
    expect(query.sql).toContain('=')
    expect(query.params).toHaveLength(1)
    expect(query.params[0]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toMatchObject([
      { queryType: 'equality' },
    ])
  })

  it('ne on column with equality config encrypts and uses <>', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.ne(usersTable.name, 'Alice')
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('<>')
    expect(query.params).toHaveLength(1)
    expect(encryptQuery).toHaveBeenCalledTimes(1)
  })

  it('gt on column with orderAndRange uses eql_v2.gt()', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.gt(usersTable.age, 25)
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.gt(')
    expect(query.params).toHaveLength(1)
    expect(query.params[0]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toMatchObject([
      { queryType: 'orderAndRange' },
    ])
  })

  it('gte on column with orderAndRange uses eql_v2.gte()', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.gte(usersTable.age, 25)
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.gte(')
  })

  it('lt on column with orderAndRange uses eql_v2.lt()', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.lt(usersTable.age, 30)
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.lt(')
  })

  it('lte on column with orderAndRange uses eql_v2.lte()', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.lte(usersTable.age, 30)
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.lte(')
  })

  it('eq on column without equality falls through to plain Drizzle eq', async () => {
    // age has orderAndRange but not equality - eq should fall through to regular Drizzle eq
    // since the code checks equality first, then orderAndRange for gt/gte/lt/lte only
    const { protectOps, dialect } = setup()

    // age column has orderAndRange but NOT equality
    const condition = await protectOps.eq(usersTable.age, 25)
    const query = dialect.sqlToQuery(condition)

    // Without equality config, eq falls through to regular Drizzle eq
    expect(query.sql).toContain('=')
  })

  it('eq on column with both equality and orderAndRange prefers equality', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    // email has both equality and orderAndRange
    const condition = await protectOps.eq(usersTable.email, 'test@example.com')
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('=')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toMatchObject([
      { queryType: 'equality' },
    ])
  })
})

// ============================================================================
// 2b. Text search operators
// ============================================================================

describe('Text search operators', () => {
  it('ilike on column with freeTextSearch uses eql_v2.ilike()', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.ilike(usersTable.bio, '%engineer%')
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.ilike(')
    expect(query.params[0]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toMatchObject([
      { queryType: 'freeTextSearch' },
    ])
  })

  it('like on column with freeTextSearch uses eql_v2.like()', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.like(usersTable.bio, '%test%')
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.like(')
  })

  it('notIlike wraps eql_v2.ilike() with NOT', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.notIlike(usersTable.bio, '%spam%')
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toMatch(/NOT.*eql_v2\.ilike\(/i)
  })

  it('ilike on column without freeTextSearch falls through to Drizzle ilike', () => {
    const { protectOps, dialect } = setup()

    // name column has equality but not freeTextSearch
    const condition = protectOps.ilike(usersTable.name, '%test%')

    // Should be synchronous (no encryption needed) since no freeTextSearch config
    expect(condition).not.toBeInstanceOf(Promise)

    const query = dialect.sqlToQuery(condition as SQL)
    expect(query.sql).toContain('ilike')
  })
})

// ============================================================================
// 2c. Range operators
// ============================================================================

describe('Range operators', () => {
  it('between on column with orderAndRange generates eql_v2.gte AND eql_v2.lte', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.between(usersTable.age, 20, 30)
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.gte(')
    expect(query.sql).toContain('eql_v2.lte(')
    // Both min and max values encrypted
    expect(query.params).toHaveLength(2)
    expect(query.params[0]).toContain('encrypted-value')
    expect(query.params[1]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalled()
  })

  it('notBetween wraps range condition with NOT', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.notBetween(usersTable.age, 20, 30)
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toMatch(/NOT/)
    expect(query.sql).toContain('eql_v2.gte(')
    expect(query.sql).toContain('eql_v2.lte(')
  })

  it('between on column without orderAndRange falls through to Drizzle between', () => {
    const { protectOps, dialect } = setup()

    // name column has equality but not orderAndRange
    const condition = protectOps.between(usersTable.name, 'A', 'Z')

    // Should be synchronous (plain Drizzle between)
    expect(condition).not.toBeInstanceOf(Promise)

    const query = dialect.sqlToQuery(condition as SQL)
    expect(query.sql).toContain('between')
  })
})

// ============================================================================
// 2d. Sorting operators
// ============================================================================

describe('Sorting operators', () => {
  it('asc on column with orderAndRange uses eql_v2.order_by()', () => {
    const { protectOps, dialect } = setup()

    const result = protectOps.asc(usersTable.age)
    const query = dialect.sqlToQuery(result)

    expect(query.sql).toContain('eql_v2.order_by(')
    expect(query.sql).toMatch(/asc/i)
  })

  it('desc on column with orderAndRange uses eql_v2.order_by()', () => {
    const { protectOps, dialect } = setup()

    const result = protectOps.desc(usersTable.age)
    const query = dialect.sqlToQuery(result)

    expect(query.sql).toContain('eql_v2.order_by(')
    expect(query.sql).toMatch(/desc/i)
  })

  it('asc on column without orderAndRange uses plain Drizzle asc', () => {
    const { protectOps, dialect } = setup()

    const result = protectOps.asc(usersTable.name)
    const query = dialect.sqlToQuery(result)

    expect(query.sql).not.toContain('eql_v2.order_by(')
  })

  it('desc on column without orderAndRange uses plain Drizzle desc', () => {
    const { protectOps, dialect } = setup()

    const result = protectOps.desc(usersTable.name)
    const query = dialect.sqlToQuery(result)

    expect(query.sql).not.toContain('eql_v2.order_by(')
  })
})

// ============================================================================
// 2e. Array operators
// ============================================================================

describe('Array operators', () => {
  it('inArray on column with equality encrypts all values', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.inArray(usersTable.name, [
      'Alice',
      'Bob',
      'Carol',
    ])
    const query = dialect.sqlToQuery(condition)

    // inArray with equality uses OR of eq() conditions
    expect(query.params.length).toBeGreaterThanOrEqual(3)
    expect(encryptQuery).toHaveBeenCalled()
  })

  it('notInArray on column with equality encrypts all values', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.notInArray(usersTable.name, [
      'Alice',
      'Bob',
    ])
    const query = dialect.sqlToQuery(condition)

    expect(query.params.length).toBeGreaterThanOrEqual(2)
    expect(encryptQuery).toHaveBeenCalled()
  })

  it('inArray batch-encrypts values in single call', async () => {
    const { encryptQuery, protectOps } = setup()

    await protectOps.inArray(usersTable.name, ['Alice', 'Bob'])

    // All values should be batch-encrypted in a single call
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    const terms = encryptQuery.mock.calls[0]?.[0] as unknown[]
    expect(terms).toHaveLength(2)
  })
})

// ============================================================================
// 2f. Error classes
// ============================================================================

describe('Error classes', () => {
  it('ProtectOperatorError stores context with tableName, columnName, operator', () => {
    const error = new ProtectOperatorError('Test error', {
      tableName: 'users',
      columnName: 'email',
      operator: 'eq',
    })

    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(ProtectOperatorError)
    expect(error.name).toBe('ProtectOperatorError')
    expect(error.message).toBe('Test error')
    expect(error.context?.tableName).toBe('users')
    expect(error.context?.columnName).toBe('email')
    expect(error.context?.operator).toBe('eq')
  })

  it('ProtectConfigError extends ProtectOperatorError', () => {
    const error = new ProtectConfigError('Config error', {
      tableName: 'users',
      columnName: 'age',
      operator: 'gt',
    })

    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(ProtectOperatorError)
    expect(error).toBeInstanceOf(ProtectConfigError)
    expect(error.name).toBe('ProtectConfigError')
    expect(error.context?.tableName).toBe('users')
  })

  it('ProtectOperatorError works without context', () => {
    const error = new ProtectOperatorError('No context')

    expect(error.message).toBe('No context')
    expect(error.context).toBeUndefined()
  })
})

// ============================================================================
// 2g. Pass-through operators
// ============================================================================

describe('Pass-through operators', () => {
  it('exists is the Drizzle exists function', () => {
    const { protectOps } = setup()

    // These should be direct references to drizzle-orm functions
    expect(typeof protectOps.exists).toBe('function')
    expect(typeof protectOps.notExists).toBe('function')
    expect(typeof protectOps.isNull).toBe('function')
    expect(typeof protectOps.isNotNull).toBe('function')
    expect(typeof protectOps.not).toBe('function')
  })

  it('arrayContains/arrayContained/arrayOverlaps are Drizzle functions', () => {
    const { protectOps } = setup()

    expect(typeof protectOps.arrayContains).toBe('function')
    expect(typeof protectOps.arrayContained).toBe('function')
    expect(typeof protectOps.arrayOverlaps).toBe('function')
  })
})

// ============================================================================
// 2h. Batched and/or
// ============================================================================

describe('Batched and/or operators', () => {
  it('protectOps.and() batches multiple encrypted operators', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.and(
      protectOps.eq(usersTable.email, 'test@example.com'),
      protectOps.gte(usersTable.age, 18),
      protectOps.ilike(usersTable.bio, '%engineer%'),
    )
    const query = dialect.sqlToQuery(condition)

    // All three conditions should be in the SQL
    expect(query.sql).toContain('=')
    expect(query.sql).toContain('eql_v2.gte(')
    expect(query.sql).toContain('eql_v2.ilike(')
    // SQL uses AND
    expect(query.sql).toContain(' and ')
    expect(encryptQuery).toHaveBeenCalled()
  })

  it('protectOps.or() batches and uses OR', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.or(
      protectOps.eq(usersTable.name, 'Alice'),
      protectOps.eq(usersTable.name, 'Bob'),
    )
    const query = dialect.sqlToQuery(condition)

    // SQL uses OR
    expect(query.sql).toContain(' or ')
    expect(query.params.length).toBeGreaterThanOrEqual(2)
    // Both eq operators trigger encryption
    expect(encryptQuery).toHaveBeenCalled()
  })

  it('protectOps.and() handles undefined conditions', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.and(
      protectOps.eq(usersTable.name, 'Alice'),
      undefined,
      protectOps.gte(usersTable.age, 18),
    )
    const query = dialect.sqlToQuery(condition)

    // Should still produce valid SQL with the non-undefined conditions
    expect(query.sql).toContain('=')
    expect(query.sql).toContain('eql_v2.gte(')
    expect(query.sql).toContain(' and ')
  })

  it('protectOps.and() with only non-encrypted conditions', async () => {
    const { protectOps } = setup()

    // Using the plain Drizzle eq (non-encrypted column fallback)
    // age has no equality, so eq falls through to Drizzle eq (synchronous)
    const eqResult = protectOps.eq(usersTable.age, 25)

    // If synchronous (non-encrypted), and() should still work
    const condition = await protectOps.and(eqResult)

    expect(condition).toBeTruthy()
  })
})

// ============================================================================
// bigint rejection — the EQL v2 integration cannot carry a native bigint
// (`@cipherstash/protect`'s query term type is `JsPlaintext | null`), so a
// bigint must fail loudly rather than silently coerce to the text "1".
// ============================================================================

describe('bigint values are rejected on the EQL v2 integration', () => {
  it('gt throws ProtectOperatorError instead of silently stringifying a bigint', async () => {
    const { protectOps } = setup()

    // `age` has orderAndRange, so `gt` takes the encrypting path and reaches
    // `toPlaintext`, where a bigint must be rejected.
    await expect(
      protectOps.gt(usersTable.age, 1n as unknown as number),
    ).rejects.toThrow(ProtectOperatorError)
    await expect(
      protectOps.gt(usersTable.age, 1n as unknown as number),
    ).rejects.toThrow(/bigint values are not supported/)
  })

  it('never reaches the encrypt client when rejecting a bigint', async () => {
    const { protectOps, encryptQuery } = setup()

    await expect(
      protectOps.gt(usersTable.age, 1n as unknown as number),
    ).rejects.toThrow(ProtectOperatorError)
    expect(encryptQuery).not.toHaveBeenCalled()
  })
})
