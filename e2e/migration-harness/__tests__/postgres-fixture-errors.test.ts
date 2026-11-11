import { expect, test, vi } from 'vitest'

const failure = vi.hoisted(() => ({
  message: 'secret-sentinel',
  type: 'DecryptError',
}))
vi.mock('@cipherstash/protect', () => ({
  csTable: (_name: string, columns: unknown) => columns,
  csColumn: () => ({
    equality() {
      return this
    },
    dataType() {
      return this
    },
  }),
  protect: async () => ({ decrypt: async () => ({ failure }) }),
}))
vi.mock('../postgres-fixture/src/stores.mjs', () => ({
  createStores: async () => ({
    sql: async () => [{ pk: 'legacy' }],
    close: async () => {},
  }),
}))

test('legacy fixture retains the provider failure privately without exporting its message', async () => {
  const modulePath = '../postgres-fixture/src/app.mjs'
  const { createApp } = await import(modulePath)
  const app = await createApp({
    CS_WORKSPACE_CRN: 'test:local',
    CS_CLIENT_ID: 'id',
    CS_CLIENT_KEY: 'key',
    CS_CLIENT_ACCESS_KEY: 'access',
  })
  await expect(app.get('legacy')).rejects.toMatchObject({
    message: 'Legacy encryption operation failed',
    cause: failure,
  })
  try {
    await app.get('legacy')
  } catch (error) {
    expect(String(error)).not.toContain('secret-sentinel')
  }
})
