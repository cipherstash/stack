import { describe, expect, it } from 'vitest'
import type { AgentEnvironment } from '../../init/detect-agents.js'
import type { InitState } from '../../init/types.js'
import {
  HANDOFF_CHOICES,
  buildOptions,
  defaultChoice,
  resolveTarget,
} from '../steps/how-to-proceed.js'

function makeAgents(claudeCode: boolean, codex: boolean): AgentEnvironment {
  return {
    cli: { claudeCode, codex },
    project: {
      claudeDir: false,
      claudeMd: false,
      claudeSkillsDir: false,
      agentsMd: false,
    },
    editor: 'unknown',
  }
}

const noAgents: InitState = { agents: makeAgents(false, false) }
const claudeOnly: InitState = { agents: makeAgents(true, false) }
const codexOnly: InitState = { agents: makeAgents(false, true) }

describe('howToProceed — buildOptions', () => {
  it('offers all four targets in implement mode', () => {
    const opts = buildOptions(noAgents, 'implement')
    const values = opts.map((o) => o.value)
    expect(values).toEqual(['claude-code', 'codex', 'agents-md', 'wizard'])
  })

  it('offers all four targets in plan mode', () => {
    const opts = buildOptions(noAgents, 'plan')
    const values = opts.map((o) => o.value)
    expect(values).toEqual(['claude-code', 'codex', 'agents-md', 'wizard'])
  })

  it('reflects detection state in hints regardless of mode', () => {
    const implement = buildOptions(claudeOnly, 'implement')
    const plan = buildOptions(claudeOnly, 'plan')

    const implementClaude = implement.find((o) => o.value === 'claude-code')
    const planClaude = plan.find((o) => o.value === 'claude-code')

    expect(implementClaude?.hint).toMatch(/detected/)
    expect(planClaude?.hint).toMatch(/detected/)
  })
})

describe('howToProceed — defaultChoice', () => {
  it('prefers claude-code when detected', () => {
    expect(defaultChoice(claudeOnly, 'implement')).toBe('claude-code')
    expect(defaultChoice(claudeOnly, 'plan')).toBe('claude-code')
  })

  it('prefers codex when claude is absent and codex is detected', () => {
    expect(defaultChoice(codexOnly, 'implement')).toBe('codex')
    expect(defaultChoice(codexOnly, 'plan')).toBe('codex')
  })

  it('falls back to agents-md in both modes when no CLI is detected', () => {
    // AGENTS.md is the broadest "works without anything else installed"
    // option, so it's the right default in either mode when no agent CLI
    // is on PATH.
    expect(defaultChoice(noAgents, 'implement')).toBe('agents-md')
    expect(defaultChoice(noAgents, 'plan')).toBe('agents-md')
  })
})

describe('howToProceed — resolveTarget', () => {
  it('accepts every documented handoff target', () => {
    for (const choice of HANDOFF_CHOICES) {
      expect(resolveTarget(choice)).toBe(choice)
    }
  })

  it('returns null for unknown values', () => {
    expect(resolveTarget('claude')).toBeNull()
    expect(resolveTarget('CLAUDE-CODE')).toBeNull()
    expect(resolveTarget('agents.md')).toBeNull()
    expect(resolveTarget('')).toBeNull()
  })

  it('returns null when the flag is absent', () => {
    expect(resolveTarget(undefined)).toBeNull()
  })
})
