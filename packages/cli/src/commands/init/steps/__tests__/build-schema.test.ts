import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitProvider, InitState } from '../../types.js'

const existsSyncMock = vi.hoisted(() => vi.fn(() => false))
const writeFileSyncMock = vi.hoisted(() => vi.fn())
vi.mock('node:fs', () => ({
  existsSync: existsSyncMock,
  mkdirSync: vi.fn(),
  writeFileSync: writeFileSyncMock,
}))
vi.mock('../../../../config/index.js', () => ({
  DEFAULT_CLIENT_PATH: 'src/encryption/index.ts',
}))
vi.mock('../../../../config/tty.js', () => ({
  isInteractive: vi.fn(() => true),
}))
// Raw-postgres integration: all detectors return false.
vi.mock('../../../db/detect.js', () => ({
  detectDrizzle: vi.fn(() => false),
  detectPrismaNext: vi.fn(() => false),
  detectSupabase: vi.fn(() => false),
}))
vi.mock('../../lib/env-keys.js', () => ({ readEnvKeyNames: vi.fn(() => []) }))
vi.mock('../../lib/write-context.js', () => ({
  writeBaselineContextFile: vi.fn(),
}))
vi.mock('../../utils.js', () => ({
  generatePlaceholderClient: vi.fn(() => '// placeholder'),
}))
vi.mock('@clack/prompts', () => ({
  select: vi.fn(async () => 'overwrite'),
  isCancel: vi.fn(() => false),
  log: { info: vi.fn(), success: vi.fn() },
}))

import * as p from '@clack/prompts'
import { isInteractive } from '../../../../config/tty.js'
import { buildSchemaStep } from '../build-schema.js'

const baseState = {
  databaseUrl: 'postgresql://localhost:5432/app',
} as unknown as InitState
const provider = { name: 'base', selected: [] } as unknown as InitProvider

describe('buildSchemaStep', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(isInteractive).mockReturnValue(true)
    existsSyncMock.mockReturnValue(false)
  })

  it('writes the placeholder client when none exists (no prompt)', async () => {
    existsSyncMock.mockReturnValue(false)

    const result = await buildSchemaStep.run(baseState, provider)

    expect(p.select).not.toHaveBeenCalled()
    expect(writeFileSyncMock).toHaveBeenCalledTimes(1)
    expect(result.schemaGenerated).toBe(true)
  })

  it('prompts on an existing file when interactive', async () => {
    existsSyncMock.mockReturnValue(true)

    await buildSchemaStep.run(baseState, provider)

    expect(p.select).toHaveBeenCalledTimes(1)
  })

  it('keeps an existing file without prompting when non-interactive (#600)', async () => {
    existsSyncMock.mockReturnValue(true)
    vi.mocked(isInteractive).mockReturnValue(false)

    const result = await buildSchemaStep.run(baseState, provider)

    // No TTY to answer; keep the user's file rather than prompt or clobber.
    expect(p.select).not.toHaveBeenCalled()
    expect(writeFileSyncMock).not.toHaveBeenCalled()
    expect(result.schemaGenerated).toBe(false)
  })

  it('forces the prisma-next integration and skips the scaffold when the `--prisma` provider is selected', async () => {
    // `--prisma` sets provider.name === 'prisma'; the internal integration
    // value stays 'prisma-next' so skill/dep/prompt wiring is unchanged.
    // Prisma Next derives its schema from contract.json, so there is no
    // placeholder client to write.
    const prismaProvider = {
      name: 'prisma',
      selected: ['prisma'],
    } as unknown as InitProvider

    const result = await buildSchemaStep.run(baseState, prismaProvider)

    expect(result.integration).toBe('prisma-next')
    expect(result.schemaGenerated).toBe(false)
    expect(writeFileSyncMock).not.toHaveBeenCalled()
  })

  it('still forces prisma-next when `--prisma` is combined with another flag', async () => {
    // `stash init --prisma --supabase` joins the flags into a single provider
    // name for referrer tracking — 'prisma-supabase', which is not 'prisma'.
    // Reading that name here dropped the run onto `detectIntegration`, and a
    // fresh project with no prisma-next config detects as raw postgres: init
    // then wrote a placeholder client Prisma Next never uses and reported an
    // integration the rest of the pipeline routes on.
    const prismaSupabase = {
      name: 'prisma-supabase',
      selected: ['supabase', 'prisma'],
    } as unknown as InitProvider

    const result = await buildSchemaStep.run(baseState, prismaSupabase)

    expect(result.integration).toBe('prisma-next')
    expect(result.schemaGenerated).toBe(false)
    expect(writeFileSyncMock).not.toHaveBeenCalled()
  })
})
