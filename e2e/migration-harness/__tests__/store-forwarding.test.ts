import { afterEach, expect, test, vi } from 'vitest'

const { createStoreSet, disposeStores, isolation } = vi.hoisted(() => ({
  createStoreSet: vi.fn(),
  disposeStores: vi.fn(async () => {}),
  isolation: {
    prove: vi.fn(async () => ({ verified: true })),
    exec: vi.fn(async () => ({ exitCode: 0, stdout: '', stderr: '' })),
    stop: vi.fn(async () => {}),
  },
}))
vi.mock('../run/real-stores.mjs', () => ({ createStoreSet, disposeStores }))
vi.mock('../isolation.mjs', () => ({ createIsolation: () => isolation }))

afterEach(() => vi.restoreAllMocks())

test('F19 store probe exercises assigned forwarding for Migrator and App Host', async () => {
  const forwards = (actor: string) => [
    {
      host: '127.0.0.1',
      port: 5432,
      targetHost: `${actor}-pg`,
      targetPort: 5432,
    },
    {
      host: '127.0.0.1',
      port: 8000,
      targetHost: `${actor}-dynamo`,
      targetPort: 8000,
    },
  ]
  createStoreSet.mockImplementation(async ({ actor }: { actor: string }) => ({
    env: { DATABASE_URL: 'postgresql://role:password@127.0.0.1:5432/database' },
    forwards: forwards(actor),
    verify: async () => ({ crossDatabaseConnectDenied: true }),
  }))
  vi.spyOn(console, 'log').mockImplementation(() => {})

  await import('../run/store-probe.mjs')

  expect(isolation.prove).toHaveBeenCalledOnce()
  for (const [actor, store] of [
    ['migrator', 'migrator'],
    ['app-host', 'oracle'],
  ]) {
    expect(isolation.exec).toHaveBeenCalledWith(
      expect.objectContaining({ actor, forwards: forwards(store) }),
    )
  }
  expect(isolation.stop).toHaveBeenCalledOnce()
  expect(disposeStores).toHaveBeenCalledOnce()
})
