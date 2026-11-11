import { afterEach, expect, it, vi } from 'vitest'

const { protect } = vi.hoisted(() => ({ protect: vi.fn() }))

vi.mock('../../e2e/node_modules/@cipherstash/protect', () => ({
  protect,
  csTable: (_name, columns) => columns,
  csColumn: () => {
    const column = {
      equality: () => column,
      dataType: () => column,
    }
    return column
  },
}))
vi.mock('../../e2e/node_modules/@cipherstash/protect-dynamodb', () => ({
  protectDynamoDB: () => ({}),
}))
vi.mock('../../e2e/migration-harness/fixture/src/stores.mjs', () => ({
  createStores: async () => ({}),
}))

import { createApp } from '../../e2e/migration-harness/fixture/src/app.mjs'

afterEach(() => {
  vi.unstubAllEnvs()
  protect.mockReset()
})

const env = (region) => ({
  CS_WORKSPACE_CRN: `crn:${region}:workspace`,
  CS_CLIENT_ID: 'test-client',
  CS_CLIENT_KEY: 'test-key',
  CS_CLIENT_ACCESS_KEY: 'test-access-key',
})

it('restores the original hosts after overlapping client initialization', async () => {
  vi.stubEnv('CS_CTS_HOST', 'https://original.cts.invalid')
  vi.stubEnv('CS_ZEROKMS_HOST', 'https://original.kms.invalid')
  const completions = []
  protect.mockImplementation(
    () => new Promise((resolve) => completions.push(resolve)),
  )
  const first = createApp(env('first'))
  const second = createApp(env('second'))
  await vi.waitFor(() => expect(completions.length).toBeGreaterThan(0))
  completions[0]({})
  await first
  await vi.waitFor(() => expect(completions).toHaveLength(2))
  completions[1]({})
  await second

  expect(process.env.CS_CTS_HOST).toBe('https://original.cts.invalid')
  expect(process.env.CS_ZEROKMS_HOST).toBe('https://original.kms.invalid')
})

it('restores absent hosts after rejection and allows a later client', async () => {
  vi.stubEnv('CS_CTS_HOST', undefined)
  vi.stubEnv('CS_ZEROKMS_HOST', undefined)
  protect.mockRejectedValueOnce(new Error('initialization failed'))
  protect.mockResolvedValueOnce({})

  await expect(createApp(env('first'))).rejects.toThrow('initialization failed')
  expect(process.env.CS_CTS_HOST).toBeUndefined()
  expect(process.env.CS_ZEROKMS_HOST).toBeUndefined()

  await createApp(env('second'))
  expect(protect).toHaveBeenCalledTimes(2)
  expect(process.env.CS_CTS_HOST).toBeUndefined()
  expect(process.env.CS_ZEROKMS_HOST).toBeUndefined()
})
