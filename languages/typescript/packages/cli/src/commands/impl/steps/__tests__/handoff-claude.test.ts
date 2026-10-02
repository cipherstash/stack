import { beforeEach, expect, it, vi } from 'vitest'
import type { InitState } from '../../../init/types.js'

// The launch prompt's skills clause is the unit under test. Mock the skill
// installer so we control whether any skills were "copied", and stub the
// artifact writer / agent spawner so no files are written and no process is
// spawned. `impl.test.ts` mocks `howToProceedStep.run` out entirely, so
// nothing there drives this prompt — this file is its dedicated coverage.
const installSkills = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/install-skills.js', () => ({ installSkills }))
vi.mock('../../../init/lib/handoff-helpers.js', () => ({
  writeArtifacts: vi.fn(),
  spawnAgent: vi.fn(async () => 0),
}))
vi.mock('@clack/prompts', () => ({
  note: vi.fn(),
  log: { success: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import * as p from '@clack/prompts'
import { handoffClaudeStep } from '../handoff-claude.js'

// `agents` undefined → Claude "not installed" path, which routes the launch
// prompt into a `p.note` (rather than spawning). That note's body is what we
// assert on.
const state = { integration: 'postgresql' } as unknown as InitState

const warnings = () => vi.mocked(p.log.warn).mock.calls.map(String).join('\n')

beforeEach(() => vi.clearAllMocks())

it('launch prompt omits the skills dir when no skills were copied', async () => {
  installSkills.mockReturnValue({ copied: [], failed: [] })
  await handoffClaudeStep.run(state)
  expect(vi.mocked(p.note).mock.calls[0][0]).not.toContain('.claude/skills/')
})

it('launch prompt names the skills dir when skills were copied', async () => {
  installSkills.mockReturnValue({ copied: ['stash-encryption'], failed: [] })
  await handoffClaudeStep.run(state)
  expect(vi.mocked(p.note).mock.calls[0][0]).toContain('.claude/skills/')
})

// Unlike the Codex handoff there is no AGENTS.md on this path to inline
// into — a failed install must be announced, not left looking complete
// (#736 follow-up review).
it('warns when skills exist but could not be installed', async () => {
  installSkills.mockReturnValue({
    copied: [],
    failed: ['stash-encryption', 'stash-cli'],
  })
  await handoffClaudeStep.run(state)
  expect(warnings()).toContain('could not be installed to .claude/skills/')
  expect(warnings()).toContain('stash-encryption, stash-cli')
})

it('does not warn when this build simply ships no skills', async () => {
  installSkills.mockReturnValue({ copied: [], failed: [] })
  await handoffClaudeStep.run(state)
  expect(p.log.warn).not.toHaveBeenCalled()
})
