import { beforeEach, expect, it, vi } from 'vitest'
import type { HandoffChoice, InitState } from '../../../init/types.js'

// `buildOptions` / `defaultChoice` / `resolveTarget` are pure and covered in
// `impl/__tests__/how-to-proceed.test.ts`. What is NOT covered there is the
// dispatch arm: a pre-resolved `state.handoff` must skip the picker and run
// the matching step. Misrouting or dropping an arm would otherwise pass CI.
const runs = vi.hoisted(() => ({
  'claude-code': vi.fn(async (s: InitState) => s),
  codex: vi.fn(async (s: InitState) => s),
  'agents-md': vi.fn(async (s: InitState) => s),
  lovable: vi.fn(async (s: InitState) => s),
  wizard: vi.fn(async (s: InitState) => s),
}))
vi.mock('../handoff-claude.js', () => ({
  handoffClaudeStep: { run: runs['claude-code'] },
}))
vi.mock('../handoff-codex.js', () => ({
  handoffCodexStep: { run: runs.codex },
}))
vi.mock('../handoff-agents-md.js', () => ({
  handoffAgentsMdStep: { run: runs['agents-md'] },
}))
vi.mock('../handoff-lovable.js', () => ({
  handoffLovableStep: { run: runs.lovable },
}))
vi.mock('../handoff-wizard.js', () => ({
  handoffWizardStep: { run: runs.wizard },
}))
const select = vi.hoisted(() => vi.fn())
vi.mock('@clack/prompts', () => ({
  select,
  isCancel: vi.fn(() => false),
  note: vi.fn(),
  log: { success: vi.fn(), info: vi.fn(), warn: vi.fn() },
}))

import { HANDOFF_CHOICES, howToProceedStep } from '../how-to-proceed.js'

beforeEach(() => {
  vi.clearAllMocks()
})

// Table-driven off HANDOFF_CHOICES so a new target that reaches the picker
// without a dispatch arm fails here rather than at runtime.
for (const choice of HANDOFF_CHOICES) {
  it(`routes a pre-resolved \`${choice}\` state to its own step, without a prompt`, async () => {
    await howToProceedStep.run({ handoff: choice } as InitState)

    expect(runs[choice]).toHaveBeenCalledTimes(1)
    // The dispatched step must see the resolved choice on the state.
    expect(runs[choice].mock.calls[0][0].handoff).toBe(choice)
    // Every other arm stays untouched.
    for (const other of HANDOFF_CHOICES) {
      if (other !== choice) expect(runs[other]).not.toHaveBeenCalled()
    }
    // A pre-resolved target is what makes the command non-TTY safe.
    expect(select).not.toHaveBeenCalled()
  })
}

it('runs the picked step when the picker is used', async () => {
  const picked: HandoffChoice = 'lovable'
  select.mockResolvedValueOnce(picked)

  await howToProceedStep.run({ agents: undefined } as InitState)

  expect(select).toHaveBeenCalledTimes(1)
  expect(runs.lovable).toHaveBeenCalledTimes(1)
  expect(runs.lovable.mock.calls[0][0].handoff).toBe('lovable')
})
