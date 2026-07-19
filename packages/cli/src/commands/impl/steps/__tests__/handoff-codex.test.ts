import { beforeEach, expect, it, vi } from 'vitest'
import type { InitState } from '../../../init/types.js'

// Same seam as the handoff-claude test: the launch prompt's skills clause is
// the unit under test. Mock the skill installer to control whether skills were
// "copied". The Codex handoff also writes AGENTS.md to disk before printing
// the prompt, so stub `node:fs` and the AGENTS.md builders to keep the test
// hermetic (no file lands in the repo) — the assertion is purely on the
// launch-prompt text.
const installSkills = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/install-skills.js', () => ({ installSkills }))
vi.mock('../../../init/lib/handoff-helpers.js', () => ({
  writeArtifacts: vi.fn(),
  spawnAgent: vi.fn(async () => 0),
}))
vi.mock('../../../init/lib/build-agents-md.js', () => ({
  buildAgentsMdBody: vi.fn(() => '# managed doctrine'),
}))
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

beforeEach(() => vi.clearAllMocks())

it('launch prompt drops .codex/skills/ but keeps AGENTS.md when no skills copied', async () => {
  installSkills.mockReturnValue([])
  await handoffCodexStep.run(state)
  const body = vi.mocked(p.note).mock.calls[0][0]
  expect(body).not.toContain('.codex/skills/')
  // The durable rules live in AGENTS.md regardless, so the prompt still names it.
  expect(body).toContain('AGENTS.md')
})

it('launch prompt names .codex/skills/ when skills were copied', async () => {
  installSkills.mockReturnValue(['stash-encryption'])
  await handoffCodexStep.run(state)
  expect(vi.mocked(p.note).mock.calls[0][0]).toContain('.codex/skills/')
})
