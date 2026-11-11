import { expect, test } from 'vitest'
import {
  postgresBehaviour,
  postgresLegacy,
} from '../run/postgres-behaviour.mjs'

test('Postgres behaviour separates read-only checks from fresh writes', async () => {
  const rows = new Map<string, Record<string, unknown>>(
    postgresLegacy.map((row) => [row.pk, row]),
  )
  const calls: string[] = []
  const result = await postgresBehaviour(async (method, args) => {
    calls.push(method)
    const value = args[0]
    if (method === 'put') {
      const row = Object.fromEntries(Object.entries(Object(value)))
      rows.set(String(row.pk), row)
      return null
    }
    if (method === 'get') return rows.get(String(value)) ?? null
    const column = method === 'findEmail' ? 'email' : 'age'
    return [...rows.values()]
      .filter((row) => row[column] === value)
      .sort((a, b) => String(a.pk).localeCompare(String(b.pk)))
  })
  expect(calls).not.toContain('put')
  expect(result.checks.every((check) => check.passed)).toBe(true)
  expect((await result.mutate()).every((check) => check.passed)).toBe(true)
  expect(calls).toContain('put')
})

test('Postgres behaviour identifies a query mapping that returns only one equal-age row', async () => {
  const result = await postgresBehaviour(async (method, args) => {
    if (method === 'get')
      return postgresLegacy.find((row) => row.pk === args[0])
    if (method === 'findEmail')
      return postgresLegacy.filter((row) => row.email === args[0])
    return postgresLegacy.filter((row) => row.age === args[0]).slice(0, 1)
  })
  expect(result.checks).toContainEqual(
    expect.objectContaining({
      id: 'behaviour.postgres-age-lookup',
      passed: false,
    }),
  )
})
