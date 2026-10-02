import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { InitState } from '../../../init/types.js'

// Same seam as the handoff-codex test, minus the launch: Lovable's agent runs
// in Lovable's cloud, so this step only writes files and prints guidance. The
// unit under test is the honesty contract between `writeAgentsMd`'s result,
// the delivery recorded into the artifacts, and what the note tells the user
// to do next.
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
import { handoffLovableStep } from '../handoff-lovable.js'

const state = { integration: 'supabase' } as unknown as InitState

const noteBody = () => String(vi.mocked(p.note).mock.calls[0][0])
const agentsMdMode = () => vi.mocked(buildAgentsMdBody).mock.calls[0][1]
const inlinedList = () => vi.mocked(buildAgentsMdBody).mock.calls[0][2]
const delivery = () => vi.mocked(writeArtifacts).mock.calls[0][3]
const handoffRecorded = () => vi.mocked(writeArtifacts).mock.calls[0][2]

beforeEach(() => {
  vi.clearAllMocks()
  writeAgentsMd.mockReturnValue(true)
  availableSkills.mockReturnValue(['stash-encryption', 'stash-supabase'])
})

describe('when AGENTS.md was written', () => {
  it('inlines the per-integration skills — Lovable does not load skill directories', async () => {
    await handoffLovableStep.run(state)
    expect(agentsMdMode()).toBe('doctrine-plus-skills')
    expect(inlinedList()).toEqual(['stash-encryption', 'stash-supabase'])
  })

  it('records the skills as inlined under the lovable handoff', async () => {
    await handoffLovableStep.run(state)
    expect(handoffRecorded()).toBe('lovable')
    expect(delivery()).toEqual({
      installed: [],
      inlined: ['stash-encryption', 'stash-supabase'],
      failed: [],
    })
  })

  it('walks the user through the GitHub sync and the Knowledge pointer', async () => {
    // Lovable only sees the repo through its GitHub sync and does not
    // auto-load AGENTS.md, so both halves have to be in the note or the
    // guidance never reaches the agent.
    await handoffLovableStep.run(state)
    const body = noteBody()
    expect(body).toContain('Commit and push')
    expect(body).toContain('Settings → Knowledge')
    expect(body).toContain('.cipherstash/setup-prompt.md')
  })
})

// The failure arm is the whole point of the honesty contract: telling the
// user to commit a file that was never written sends them hunting for it.
describe('when AGENTS.md could not be written', () => {
  beforeEach(() => {
    writeAgentsMd.mockReturnValue(false)
  })

  it('records the skills as failed, not inlined', async () => {
    await handoffLovableStep.run(state)
    expect(delivery()).toEqual({
      installed: [],
      inlined: [],
      failed: ['stash-encryption', 'stash-supabase'],
    })
  })

  it('says the write failed instead of telling the user to commit it', async () => {
    await handoffLovableStep.run(state)
    const body = noteBody()
    expect(body).toContain('could not be written')
    expect(body).not.toContain('Commit and push')
  })

  it('still points at the artifacts that did land', async () => {
    await handoffLovableStep.run(state)
    const body = noteBody()
    expect(body).toContain('.cipherstash/setup-prompt.md')
    expect(body).toContain('.cipherstash/context.json')
  })
})

// A stripped CLI build ships no skills. AGENTS.md still carries the doctrine,
// so the guidance stands — there is just nothing to inline.
it('records an empty delivery when this build ships no skills', async () => {
  availableSkills.mockReturnValue([])
  await handoffLovableStep.run(state)
  expect(delivery()).toEqual({ installed: [], inlined: [], failed: [] })
  expect(noteBody()).toContain('Settings → Knowledge')
})
