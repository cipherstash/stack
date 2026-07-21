import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitState } from '../../../init/types.js'

// Same seam as the handoff-claude test: the launch prompt's skills clause is
// the unit under test. Mock the skill installer to control whether skills were
// "copied". The Codex handoff also writes AGENTS.md to disk before printing
// the prompt, so stub `node:fs` and the AGENTS.md builders to keep the test
// hermetic (no file lands in the repo) — the assertions are on the
// launch-prompt text and the AGENTS.md mode chosen.
const installSkills = vi.hoisted(() => vi.fn())
const availableSkills = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/install-skills.js', () => ({
  installSkills,
  availableSkills,
}))
vi.mock('../../../init/lib/handoff-helpers.js', () => ({
  writeArtifacts: vi.fn(),
  spawnAgent: vi.fn(async () => 0),
}))
// Typed with both parameters so `mock.calls[0][1]` (the AGENTS.md mode, which
// is what the fallback actually switches) type-checks.
const buildAgentsMdBody = vi.hoisted(() =>
  vi.fn((_integration: string, _mode: string) => '# managed doctrine'),
)
vi.mock('../../../init/lib/build-agents-md.js', () => ({ buildAgentsMdBody }))
vi.mock('../../../init/lib/sentinel-upsert.js', () => ({
  upsertManagedBlock: vi.fn(() => '# AGENTS.md'),
}))
vi.mock('node:fs', () => ({
  existsSync: vi.fn(() => false),
  readFileSync: vi.fn(() => ''),
  writeFileSync: vi.fn(),
}))
vi.mock('@clack/prompts', () => ({
  note: vi.fn(),
  log: { success: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import * as p from '@clack/prompts'
import { handoffCodexStep } from '../handoff-codex.js'

// `agents` undefined → Codex "not installed" path, which routes the launch
// prompt into a `p.note`.
const state = { integration: 'postgresql' } as unknown as InitState

const promptBody = () => vi.mocked(p.note).mock.calls[0][0]
const agentsMdMode = () => vi.mocked(buildAgentsMdBody).mock.calls[0][1]
const warnings = () => vi.mocked(p.log.warn).mock.calls.map(String).join('\n')

beforeEach(() => vi.clearAllMocks())

it('launch prompt names .codex/skills/ when skills were copied', async () => {
  installSkills.mockReturnValue(['stash-encryption'])
  availableSkills.mockReturnValue(['stash-encryption'])
  await handoffCodexStep.run(state)

  expect(promptBody()).toContain('.codex/skills/')
  // Skills are on disk, so AGENTS.md stays doctrine-only per Codex guidance.
  expect(agentsMdMode()).toBe('doctrine-only')
})

// #736: Codex sandboxes deny writes under `.codex/`. The skills cannot land,
// but AGENTS.md (project root) can — so the guidance is inlined there rather
// than lost, and Codex is pointed at it.
describe('when .codex/skills could not be written', () => {
  beforeEach(() => {
    installSkills.mockReturnValue([])
    availableSkills.mockReturnValue(['stash-encryption', 'stash-cli'])
  })

  it('inlines the skills into AGENTS.md instead of shipping nothing', async () => {
    await handoffCodexStep.run(state)
    expect(agentsMdMode()).toBe('doctrine-plus-skills')
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
})

// A stripped CLI build ships no skills at all. Nothing to copy AND nothing to
// inline — claiming a fallback here would be a false success of the kind #714
// and #687 removed elsewhere in init.
describe('when this build ships no skills at all', () => {
  beforeEach(() => {
    installSkills.mockReturnValue([])
    availableSkills.mockReturnValue([])
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

  it('does not claim an inline fallback happened', async () => {
    await handoffCodexStep.run(state)
    expect(warnings()).not.toContain('inlining')
  })
})
