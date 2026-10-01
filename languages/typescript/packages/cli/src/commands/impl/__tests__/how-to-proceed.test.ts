import { describe, expect, it } from 'vitest'
import type { AgentEnvironment } from '../../init/detect-agents.js'
import type { InitState } from '../../init/types.js'
import {
  buildOptions,
  defaultChoice,
  HANDOFF_CHOICES,
  resolveTarget,
  resolveTargetFlag,
} from '../steps/how-to-proceed.js'

function makeAgents(claudeCode: boolean, codex: boolean): AgentEnvironment {
  return {
    cli: { claudeCode, codex },
    project: {
      claudeDir: false,
      claudeMd: false,
      claudeSkillsDir: false,
      codexDir: false,
      agentsMd: false,
    },
    editor: 'unknown',
  }
}

const noAgents: InitState = { agents: makeAgents(false, false) }
const claudeOnly: InitState = { agents: makeAgents(true, false) }
const codexOnly: InitState = { agents: makeAgents(false, true) }

describe('howToProceed — buildOptions', () => {
  it('offers all five targets in implement mode', () => {
    const opts = buildOptions(noAgents, 'implement')
    const values = opts.map((o) => o.value)
    expect(values).toEqual([
      'claude-code',
      'codex',
      'agents-md',
      'lovable',
      'wizard',
    ])
  })

  it('offers all five targets in plan mode', () => {
    const opts = buildOptions(noAgents, 'plan')
    const values = opts.map((o) => o.value)
    expect(values).toEqual([
      'claude-code',
      'codex',
      'agents-md',
      'lovable',
      'wizard',
    ])
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

/**
 * `--target` is accepted by three commands, and the validation had been
 * hand-copied into each — which is how `plan` and `impl` kept this bug after
 * `init` was fixed. Testing the shared helper covers all three.
 *
 * The distinction that matters is "absent" versus "present but unusable".
 * `parseArgs` files a trailing `--target` (nothing followed it) under `flags`
 * as `true`, and `--target=` under `values` as an empty string. Testing the
 * value for truthiness alone reads both as absent, so the command silently
 * does whatever it does with no flag at all — for `init`, writing skills to an
 * auto-detected directory the user had just declined by naming another.
 */
describe('howToProceed — resolveTargetFlag', () => {
  it('passes a valid target through', () => {
    expect(resolveTargetFlag({}, { target: 'codex' })).toEqual({
      target: 'codex',
      error: null,
    })
  })

  it('treats an absent flag as neither a target nor an error', () => {
    expect(resolveTargetFlag({}, {})).toEqual({ target: null, error: null })
  })

  it('rejects a trailing `--target`, which parseArgs files under flags', () => {
    const { target, error } = resolveTargetFlag({ target: true }, {})
    expect(target).toBeNull()
    expect(error).toContain('needs a value')
  })

  it('rejects an empty `--target=`', () => {
    const { target, error } = resolveTargetFlag({}, { target: '' })
    expect(target).toBeNull()
    expect(error).toContain('needs a value')
  })

  it('reports an unknown value differently from a missing one', () => {
    const { target, error } = resolveTargetFlag({}, { target: 'emacs' })
    expect(target).toBeNull()
    expect(error).toContain('Unknown --target `emacs`')
    expect(error).not.toContain('needs a value')
  })

  it.each([
    ['a trailing flag', { target: true }, {}],
    ['an empty value', {}, { target: '' }],
    ['an unknown value', {}, { target: 'emacs' }],
  ])('lists the valid values when rejecting %s', (_label, flags, values) => {
    const { error } = resolveTargetFlag(flags, values)
    for (const choice of HANDOFF_CHOICES) expect(error).toContain(choice)
  })

  // An unrelated boolean flag must not be mistaken for the target flag.
  it('ignores other flags', () => {
    expect(resolveTargetFlag({ yes: true }, {})).toEqual({
      target: null,
      error: null,
    })
  })
})
