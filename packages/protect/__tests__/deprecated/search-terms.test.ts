import 'dotenv/config'
import { csColumn, csTable } from '@cipherstash/schema'
import { describe, expect, it } from 'vitest'
import { protect, type SearchTerm } from '../../src'

const users = csTable('users', {
  email: csColumn('email').freeTextSearch().equality().orderAndRange(),
  address: csColumn('address').freeTextSearch(),
  age: csColumn('age').dataType('number').equality(),
  score: csColumn('score').dataType('number').equality(),
})

describe('createSearchTerms (deprecated - backward compatibility)', () => {
  it('should create search terms with default return type', async () => {
    const protectClient = await protect({ schemas: [users] })

    const searchTerms = [
      {
        value: 'hello',
        column: users.email,
        table: users,
      },
      {
        value: 'world',
        column: users.address,
        table: users,
      },
    ] as SearchTerm[]

    const searchTermsResult = await protectClient.createSearchTerms(searchTerms)

    if (searchTermsResult.failure) {
      throw new Error(`[protect]: ${searchTermsResult.failure.message}`)
    }

    expect(searchTermsResult.data).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          v: 2,
        }),
      ]),
    )
  }, 30000)

  it('should create search terms with composite-literal return type', async () => {
    const protectClient = await protect({ schemas: [users] })

    const searchTerms = [
      {
        value: 'hello',
        column: users.email,
        table: users,
        returnType: 'composite-literal',
      },
    ] as SearchTerm[]

    const searchTermsResult = await protectClient.createSearchTerms(searchTerms)

    if (searchTermsResult.failure) {
      throw new Error(`[protect]: ${searchTermsResult.failure.message}`)
    }

    const result = searchTermsResult.data[0] as string
    expect(result).toMatch(/^\(.*\)$/)
    expect(() => JSON.parse(result.slice(1, -1))).not.toThrow()
  }, 30000)

  it('should create search terms with escaped-composite-literal return type', async () => {
    const protectClient = await protect({ schemas: [users] })

    const searchTerms = [
      {
        value: 'hello',
        column: users.email,
        table: users,
        returnType: 'escaped-composite-literal',
      },
    ] as SearchTerm[]

    const searchTermsResult = await protectClient.createSearchTerms(searchTerms)

    if (searchTermsResult.failure) {
      throw new Error(`[protect]: ${searchTermsResult.failure.message}`)
    }

    const result = searchTermsResult.data[0] as string
    expect(result).toMatch(/^".*"$/)
    const unescaped = JSON.parse(result)
    expect(unescaped).toMatch(/^\(.*\)$/)
    expect(() => JSON.parse(unescaped.slice(1, -1))).not.toThrow()
  }, 30000)

  it('should create search terms with composite-literal return type for numbers', async () => {
    const protectClient = await protect({ schemas: [users] })

    const searchTerms = [
      {
        value: 42,
        column: users.age,
        table: users,
        returnType: 'composite-literal' as const,
      },
    ]

    const searchTermsResult = await protectClient.createSearchTerms(searchTerms)

    if (searchTermsResult.failure) {
      throw new Error(`[protect]: ${searchTermsResult.failure.message}`)
    }

    const result = searchTermsResult.data[0] as string
    expect(result).toMatch(/^\(.*\)$/)
    expect(() => JSON.parse(result.slice(1, -1))).not.toThrow()
  }, 30000)

  it('should create search terms with escaped-composite-literal return type for numbers', async () => {
    const protectClient = await protect({ schemas: [users] })

    const searchTerms = [
      {
        value: 99,
        column: users.score,
        table: users,
        returnType: 'escaped-composite-literal' as const,
      },
    ]

    const searchTermsResult = await protectClient.createSearchTerms(searchTerms)

    if (searchTermsResult.failure) {
      throw new Error(`[protect]: ${searchTermsResult.failure.message}`)
    }

    const result = searchTermsResult.data[0] as string
    expect(result).toMatch(/^".*"$/)
    const unescaped = JSON.parse(result)
    expect(unescaped).toMatch(/^\(.*\)$/)
    expect(() => JSON.parse(unescaped.slice(1, -1))).not.toThrow()
  }, 30000)
})
