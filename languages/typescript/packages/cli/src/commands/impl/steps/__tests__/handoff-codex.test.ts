import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitState } from '../../../init/types.js'

// Same seam as the handoff-claude test: the launch prompt's skills clause is
// the unit under test. Mock the skill installer to control the copied/failed
// split, and the shared AGENTS.md writer to control whether the inline
// fallback landed. The assertions are on the launch-prompt text, the
// AGENTS.md mode chosen, and the delivery recorded into the artifacts.
const installSkills = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/install-skills.js', () => ({ installSkills }))
const writeAgentsMd = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/handoff-helpers.js', () => ({
  AGENTS_MD_REL_PATH: 'AGENTS.md',
  writeAgentsMd,
  writeArtifacts: vi.fn(),
  spawnAgent: vi.fn(async () => 0),
}))
const buildAgentsMdBody = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/build-agents-md.js', () => ({ buildAgentsMdBody }))
vi.mock('node:fs', () => ({
  existsSync: vi.fn(() => false),
  mkdirSync: vi.fn(),
  readFileSync: vi.fn(() => ''),
  writeFileSync: vi.fn(),
}))
vi.mock('@clack/prompts', () => ({
  note: vi.fn(),
  log: { success: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import * as p from '@clack/prompts'
import { writeArtifacts } from '../../../init/lib/handoff-helpers.js'
import { handoffCodexStep } from '../handoff-codex.js'

// `agents` undefined → Codex "not installed" path, which routes the launch
// prompt into a `p.note`.
const state = { integration: 'postgresql' } as unknown as InitState

const promptBody = () => vi.mocked(p.note).mock.calls[0][0]
const agentsMdMode = () => vi.mocked(buildAgentsMdBody).mock.calls[0][1]
const inlinedList = () => vi.mocked(buildAgentsMdBody).mock.calls[0][2]
const delivery = () => vi.mocked(writeArtifacts).mock.calls[0][3]
const warnings = () => vi.mocked(p.log.warn).mock.calls.map(String).join('\n')

beforeEach(() => {
  vi.clearAllMocks()
  writeAgentsMd.mockReturnValue(true)
})

it('launch prompt names .codex/skills/ when all skills were copied', async () => {
  installSkills.mockReturnValue({ copied: ['stash-encryption'], failed: [] })
  await handoffCodexStep.run(state)

  expect(promptBody()).toContain('.codex/skills/')
  // Skills are on disk, so AGENTS.md stays doctrine-only per Codex guidance.
  expect(agentsMdMode()).toBe('doctrine-only')
  expect(delivery()).toEqual({
    installed: ['stash-encryption'],
    inlined: [],
    failed: [],
  })
})

// #736: Codex sandboxes deny writes under `.codex/`. The skills cannot land,
// but AGENTS.md (project root) can — so the guidance is inlined there rather
// than lost, and Codex is pointed at it.
describe('when .codex/skills could not be written at all', () => {
  beforeEach(() => {
    installSkills.mockReturnValue({
      copied: [],
      failed: ['stash-encryption', 'stash-cli'],
    })
  })

  it('inlines the failed skills into AGENTS.md instead of shipping nothing', async () => {
    await handoffCodexStep.run(state)
    expect(agentsMdMode()).toBe('doctrine-plus-skills')
    expect(inlinedList()).toEqual(['stash-encryption', 'stash-cli'])
  })

  it('points the launch prompt at AGENTS.md, not the directory that failed', async () => {
    await handoffCodexStep.run(state)
    const body = promptBody()
    expect(body).not.toContain('.codex/skills/')
    expect(body).toContain('inlined in AGENTS.md')
  })

  it('says so, rather than reporting a silent success', async () => {
    await handoffCodexStep.run(state)
    expect(warnings()).toContain('.codex/skills/')
    expect(warnings()).toContain('AGENTS.md')
  })

  it('records the skills as inlined, not installed, in the artifacts', async () => {
    await handoffCodexStep.run(state)
    expect(delivery()).toEqual({
      installed: [],
      inlined: ['stash-encryption', 'stash-cli'],
      failed: [],
    })
  })

  it('records the skills as failed when AGENTS.md could not be written either', async () => {
    writeAgentsMd.mockReturnValue(false)
    await handoffCodexStep.run(state)
    expect(delivery()).toEqual({
      installed: [],
      inlined: [],
      failed: ['stash-encryption', 'stash-cli'],
    })
    // Nothing was inlined, so the prompt must not claim otherwise.
    expect(promptBody()).not.toContain('inlined in AGENTS.md')
  })
})

// A partial copy — mkdir succeeded, one skill's cpSync failed — must inline
// exactly the missing skill, not declare success and drop it (#736 follow-up
// review: the fallback used to be all-or-nothing on installed.length === 0).
describe('when only some skills could be written', () => {
  beforeEach(() => {
    installSkills.mockReturnValue({
      copied: ['stash-encryption'],
      failed: ['stash-cli'],
    })
  })

  it('inlines only the failed skill', async () => {
    await handoffCodexStep.run(state)
    expect(agentsMdMode()).toBe('doctrine-plus-skills')
    expect(inlinedList()).toEqual(['stash-cli'])
  })

  it('points the launch prompt at both locations', async () => {
    await handoffCodexStep.run(state)
    const body = promptBody()
    expect(body).toContain('.codex/skills/')
    expect(body).toContain('inlined in AGENTS.md')
  })

  it('records the split delivery in the artifacts', async () => {
    await handoffCodexStep.run(state)
    expect(delivery()).toEqual({
      installed: ['stash-encryption'],
      inlined: ['stash-cli'],
      failed: [],
    })
  })
})

// A stripped CLI build ships no skills at all. Nothing to copy AND nothing to
// inline — claiming a fallback here would be a false success of the kind #714
// and #687 removed elsewhere in init.
describe('when this build ships no skills at all', () => {
  beforeEach(() => {
    installSkills.mockReturnValue({ copied: [], failed: [] })
  })

  it('stays doctrine-only — there is nothing to inline', async () => {
    await handoffCodexStep.run(state)
    expect(agentsMdMode()).toBe('doctrine-only')
  })

  it('drops the skills clause but still names AGENTS.md for the durable rules', async () => {
    await handoffCodexStep.run(state)
    const body = promptBody()
    expect(body).not.toContain('.codex/skills/')
    expect(body).not.toContain('inlined in AGENTS.md')
    expect(body).toContain('AGENTS.md')
  })

  it('does not warn at all — there is no fallback to announce', async () => {
    await handoffCodexStep.run(state)
    expect(p.log.warn).not.toHaveBeenCalled()
  })
})
