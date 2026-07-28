import { beforeEach, describe, expect, it, vi } from 'vitest'

// Prisma Next projects have no hand-authored encryption client file — the
// schema lives in the emitted contract.json (#<issue>). `loadEncryptionContext`
// must derive the v3 schemas from the contract (mirroring the runtime's
// `cipherstashFromStack`) instead of hard-failing on the missing file, and
// `backfillCommand` must create `cipherstash.cs_migrations` itself because the
// Prisma Next EQL install path never runs `stash eql install`.

const fsMocks = vi.hoisted(() => ({
  existsSync: vi.fn((_p: string) => false),
  readFileSync: vi.fn((_p: string) => '{}'),
}))
vi.mock('node:fs', () => ({ default: fsMocks }))

const detectPrismaNextMock = vi.hoisted(() => vi.fn(() => false))
vi.mock('@/commands/db/detect.js', () => ({
  detectPrismaNext: detectPrismaNextMock,
  detectDrizzle: vi.fn(() => false),
}))

const requireUsableEncryptConfigMock = vi.hoisted(() =>
  vi.fn((config: unknown) => config),
)
vi.mock('@/config/index.js', () => ({
  loadStashConfig: vi.fn(async () => ({
    databaseUrl: 'postgres://test',
    client: './src/encryption/index.ts',
  })),
  requireUsableEncryptConfig: requireUsableEncryptConfigMock,
}))

vi.mock('@/commands/init/utils.js', () => ({
  detectPackageManager: vi.fn(() => 'npm'),
  runnerCommand: vi.fn((_pm: string, ref: string) => `npx ${ref}`),
}))

vi.mock('@clack/prompts', () => ({
  intro: vi.fn(),
  outro: vi.fn(),
  confirm: vi.fn(async () => true),
  isCancel: vi.fn(() => false),
  log: {
    info: vi.fn(),
    success: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    step: vi.fn(),
  },
  note: vi.fn(),
}))

const encryptionClientStub = vi.hoisted(() => ({
  getEncryptConfig: vi.fn(() => ({ v: 2, tables: {} })),
}))
const deriveStackSchemasV3Mock = vi.hoisted(() =>
  vi.fn((_contract: unknown): unknown[] => []),
)
const encryptionMock = vi.hoisted(() => vi.fn(async () => encryptionClientStub))
const jitiImportMock = vi.hoisted(() =>
  vi.fn(async (specifier: string) => {
    if (specifier === '@cipherstash/stack-prisma/v3') {
      return { deriveStackSchemasV3: deriveStackSchemasV3Mock }
    }
    if (specifier === '@cipherstash/stack/v3') {
      return { Encryption: encryptionMock }
    }
    throw new Error(`unexpected jiti import: ${specifier}`)
  }),
)
vi.mock('jiti', () => ({
  createJiti: vi.fn(() => ({ import: jitiImportMock })),
}))

const queryMock = vi.hoisted(() =>
  vi.fn(async (_sql: string) => ({ rows: [] as unknown[] })),
)
vi.mock('pg', () => ({
  default: {
    Pool: class {
      connect = vi.fn(async () => ({ query: queryMock, release: vi.fn() }))
      end = vi.fn(async () => {})
    },
  },
}))

// The workspace `@cipherstash/stack` package resolves via its built dist in
// CI; mock the `schema` subpath with a zod enum matching the shape
// `translateCastAs` needs so this test doesn't depend on a prior build.
vi.mock('@cipherstash/stack/schema', async () => {
  const { z } = await import('zod')
  return {
    castAsEnum: z.enum(['string', 'text', 'number', 'bigint']).default('text'),
    toEqlCastAs: vi.fn((v: string) => v),
  }
})

const migrateMocks = vi.hoisted(() => ({
  appendEvent: vi.fn(async () => {}),
  detectColumnEqlVersion: vi.fn(async () => 3),
  installMigrationsSchema: vi.fn(async () => {}),
  progress: vi.fn(async () => ({ phase: 'dual-writing' })),
  runBackfill: vi.fn(async () => ({ rowsProcessed: 0, rowsTotal: 0 })),
  upsertManifestColumn: vi.fn(async () => {}),
}))
vi.mock('@cipherstash/migrate', () => migrateMocks)

import { loadEncryptionContext } from '../context.js'

const FAKE_TABLE = {
  tableName: 'transaction',
  build: () => ({
    tableName: 'transaction',
    columns: { email_encrypted: { cast_as: 'text' } },
  }),
}

/** process.exit that throws, so exit paths terminate the code under test. */
function spyExit() {
  return vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${code}`)
  }) as never)
}

function spyConsoleError() {
  return vi.spyOn(console, 'error').mockImplementation(() => {})
}

beforeEach(() => {
  vi.clearAllMocks()
  fsMocks.existsSync.mockImplementation(() => false)
  fsMocks.readFileSync.mockImplementation(() => '{}')
  detectPrismaNextMock.mockReturnValue(false)
  deriveStackSchemasV3Mock.mockReturnValue([])
})

describe('loadEncryptionContext — Prisma Next contract derivation', () => {
  it('still hard-fails on a missing client file outside Prisma Next projects', async () => {
    const exit = spyExit()
    const consoleError = spyConsoleError()

    await expect(loadEncryptionContext()).rejects.toThrow('process.exit:1')
    expect(consoleError).toHaveBeenCalledWith(
      expect.stringContaining('Encrypt client file not found'),
    )
    expect(jitiImportMock).not.toHaveBeenCalled()

    exit.mockRestore()
    consoleError.mockRestore()
  })

  it('derives tables and client from contract.json in a Prisma Next project', async () => {
    detectPrismaNextMock.mockReturnValue(true)
    fsMocks.existsSync.mockImplementation((p: string) =>
      p.endsWith('src/prisma/contract.json'),
    )
    fsMocks.readFileSync.mockReturnValue('{"storage":{}}')
    deriveStackSchemasV3Mock.mockReturnValue([FAKE_TABLE])

    const ctx = await loadEncryptionContext()

    expect(deriveStackSchemasV3Mock).toHaveBeenCalledWith({ storage: {} })
    expect(encryptionMock).toHaveBeenCalledWith({ schemas: [FAKE_TABLE] })
    expect(requireUsableEncryptConfigMock).toHaveBeenCalled()
    expect(ctx.client).toBe(encryptionClientStub)
    expect(ctx.tables.get('transaction')).toBe(FAKE_TABLE)
  })

  it('errors with `contract emit` guidance when no contract.json exists', async () => {
    detectPrismaNextMock.mockReturnValue(true)
    const exit = spyExit()
    const consoleError = spyConsoleError()

    await expect(loadEncryptionContext()).rejects.toThrow('process.exit:1')
    expect(consoleError).toHaveBeenCalledWith(
      expect.stringContaining('prisma-next contract emit'),
    )

    exit.mockRestore()
    consoleError.mockRestore()
  })

  it('errors when the contract has no cipherstash columns', async () => {
    detectPrismaNextMock.mockReturnValue(true)
    fsMocks.existsSync.mockImplementation((p: string) =>
      p.endsWith('prisma/contract.json'),
    )
    deriveStackSchemasV3Mock.mockReturnValue([])
    const exit = spyExit()
    const consoleError = spyConsoleError()

    await expect(loadEncryptionContext()).rejects.toThrow('process.exit:1')
    expect(consoleError).toHaveBeenCalledWith(
      expect.stringContaining('No cipherstash-encrypted columns'),
    )

    exit.mockRestore()
    consoleError.mockRestore()
  })
})

describe('backfillCommand — cs_migrations bootstrap', () => {
  it('installs the migrations schema before running the backfill', async () => {
    detectPrismaNextMock.mockReturnValue(true)
    fsMocks.existsSync.mockImplementation((p: string) =>
      p.endsWith('src/prisma/contract.json'),
    )
    deriveStackSchemasV3Mock.mockReturnValue([FAKE_TABLE])

    const { backfillCommand } = await import('../backfill.js')
    await backfillCommand({
      table: 'transaction',
      column: 'email',
      pkColumn: 'id',
      confirmDualWritesDeployed: true,
    })

    expect(migrateMocks.installMigrationsSchema).toHaveBeenCalledTimes(1)
    expect(migrateMocks.runBackfill).toHaveBeenCalledTimes(1)
    const installOrder =
      migrateMocks.installMigrationsSchema.mock.invocationCallOrder[0]!
    const backfillOrder = migrateMocks.runBackfill.mock.invocationCallOrder[0]!
    expect(installOrder).toBeLessThan(backfillOrder)
  })
})
