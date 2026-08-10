import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitState } from '../../../init/types.js'

// Same seam as the handoff-codex test. This step launches nothing — it writes
// the artifacts for an editor agent (Cursor / Windsurf / Cline) and prints the
// guidance — so the unit under test is the honesty contract between
// `writeAgentsMd`'s result, the recorded delivery, and the note.
const availableSkills = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/install-skills.js', () => ({ availableSkills }))
const writeAgentsMd = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/handoff-helpers.js', () => ({
  AGENTS_MD_REL_PATH: 'AGENTS.md',
  writeAgentsMd,
  writeArtifacts: vi.fn(),
}))
const buildAgentsMdBody = vi.hoisted(() => vi.fn())
vi.mock('../../../init/lib/build-agents-md.js', () => ({ buildAgentsMdBody }))
vi.mock('@clack/prompts', () => ({
  note: vi.fn(),
  log: { success: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import * as p from '@clack/prompts'
import { writeArtifacts } from '../../../init/lib/handoff-helpers.js'
import { handoffAgentsMdStep } from '../handoff-agents-md.js'

const state = { integration: 'drizzle' } as unknown as InitState

const noteBody = () => String(vi.mocked(p.note).mock.calls[0][0])
const agentsMdMode = () => vi.mocked(buildAgentsMdBody).mock.calls[0][1]
const delivery = () => vi.mocked(writeArtifacts).mock.calls[0][3]
const handoffRecorded = () => vi.mocked(writeArtifacts).mock.calls[0][2]

beforeEach(() => {
  vi.clearAllMocks()
  writeAgentsMd.mockReturnValue(true)
  availableSkills.mockReturnValue(['stash-encryption', 'stash-drizzle'])
})

describe('when AGENTS.md was written', () => {
  it('inlines the skills — these agents do not auto-load skill directories', async () => {
    await handoffAgentsMdStep.run(state)
    expect(agentsMdMode()).toBe('doctrine-plus-skills')
    expect(handoffRecorded()).toBe('agents-md')
    expect(delivery()).toEqual({
      installed: [],
      inlined: ['stash-encryption', 'stash-drizzle'],
      failed: [],
    })
  })

  it('tells the user their editor agent picks the file up automatically', async () => {
    await handoffAgentsMdStep.run(state)
    const body = noteBody()
    expect(body).toContain('pick up AGENTS.md automatically')
    expect(body).toContain('.cipherstash/setup-prompt.md')
  })
})

describe('when AGENTS.md could not be written', () => {
  beforeEach(() => {
    writeAgentsMd.mockReturnValue(false)
  })

  it('records the skills as failed, not inlined', async () => {
    await handoffAgentsMdStep.run(state)
    expect(delivery()).toEqual({
      installed: [],
      inlined: [],
      failed: ['stash-encryption', 'stash-drizzle'],
    })
  })

  it('does not claim an agent will pick up a file that was never written', async () => {
    await handoffAgentsMdStep.run(state)
    const body = noteBody()
    expect(body).toContain('could not be written')
    expect(body).not.toContain('pick up AGENTS.md automatically')
  })
})
