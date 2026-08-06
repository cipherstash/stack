import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'

vi.mock('@cipherstash/protect-ffi', () => ({
  // 0.31 replaced the `ProtectError` class with this guard; `getErrorCode`
  // reaches it on the failure path. The preflight rejects before the FFI, so
  // the errors here carry no `code` and the predicate is never satisfied.
  isProtectErrorCode: (value: unknown) =>
    typeof value === 'string' && value === 'UNKNOWN_COLUMN',
  newClient: vi.fn(async () => ({ __mock: 'client' })),
  encryptQuery: vi.fn(async () => ({ v: 3, bf: [1] })),
  encryptQueryBulk: vi.fn(async () => [{ v: 3, bf: [1] }]),
}))

import * as ffi from '@cipherstash/protect-ffi'

const users = encryptedTable('users', {
  bio: types.TextMatch('bio'),
})

let previousWorkspaceCrn: string | undefined

beforeEach(() => {
  vi.clearAllMocks()
  previousWorkspaceCrn = process.env.CS_WORKSPACE_CRN
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
})

afterEach(() => {
  if (previousWorkspaceCrn === undefined) delete process.env.CS_WORKSPACE_CRN
  else process.env.CS_WORKSPACE_CRN = previousWorkspaceCrn
})

describe('core v3 match-needle preflight', () => {
  it('rejects a short scalar needle without calling protect-ffi', async () => {
    const client = await Encryption({ schemas: [users] })
    const result = await client.encryptQuery('ad', {
      column: users.bio,
      table: users,
      queryType: 'freeTextSearch',
    })

    expect(result.failure?.message).toMatch(/at least 3 characters/)
    expect(ffi.encryptQuery).not.toHaveBeenCalled()
  })

  it('rejects a short term in a batch before calling protect-ffi', async () => {
    const client = await Encryption({ schemas: [users] })
    const result = await client.encryptQuery([
      {
        value: 'ad',
        column: users.bio,
        table: users,
        queryType: 'freeTextSearch',
      },
    ])

    expect(result.failure?.message).toMatch(/at least 3 characters/)
    expect(ffi.encryptQueryBulk).not.toHaveBeenCalled()
  })
})
