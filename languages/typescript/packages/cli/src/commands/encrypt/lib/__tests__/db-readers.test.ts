/**
 * The pre-install tolerance in `latestByColumnSafe` and `progressSafe`: a
 * missing `cipherstash.cs_migrations` reads as "no events", and every other
 * error reaches the caller. The distinction is the SQLSTATE, not the message:
 * "permission denied for table cs_migrations" names the table too, and
 * reading it as "no history" would hide an open migration from the refusals
 * that depend on it.
 */

import type pg from 'pg'
import { describe, expect, it } from 'vitest'
import { latestByColumnSafe, progressSafe } from '../db-readers.js'

/** A `pg` error: the driver sets `code` to the server's SQLSTATE. */
function pgError(code: string, message: string): Error {
  return Object.assign(new Error(message), { code })
}

function failingClient(error: Error): pg.ClientBase {
  return {
    query: () => Promise.reject(error),
  } as unknown as pg.ClientBase
}

const missingTable = pgError(
  '42P01',
  'relation "cipherstash.cs_migrations" does not exist',
)
const permissionDenied = pgError(
  '42501',
  'permission denied for table cs_migrations',
)
const permissionDeniedSchema = pgError(
  '42501',
  'permission denied for schema cipherstash',
)

describe('progressSafe', () => {
  it('reads a missing cs_migrations table as no events', async () => {
    await expect(
      progressSafe(failingClient(missingTable), 'users', 'email'),
    ).resolves.toBeNull()
  })

  it('rethrows a permission error that names the table', async () => {
    await expect(
      progressSafe(failingClient(permissionDenied), 'users', 'email'),
    ).rejects.toBe(permissionDenied)
  })

  it('rethrows a permission error on the cipherstash schema', async () => {
    await expect(
      progressSafe(failingClient(permissionDeniedSchema), 'users', 'email'),
    ).rejects.toBe(permissionDeniedSchema)
  })
})

describe('latestByColumnSafe', () => {
  it('reads a missing cs_migrations table as no events', async () => {
    await expect(
      latestByColumnSafe(failingClient(missingTable)),
    ).resolves.toEqual(new Map())
  })

  it('rethrows a permission error that names the table', async () => {
    await expect(
      latestByColumnSafe(failingClient(permissionDenied)),
    ).rejects.toBe(permissionDenied)
  })
})
