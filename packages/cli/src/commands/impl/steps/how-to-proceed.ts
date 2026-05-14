import * as p from '@clack/prompts'
import {
  CancelledError,
  type HandoffChoice,
  type HandoffStep,
  type InitMode,
  type InitState,
} from '../../init/types.js'
import { handoffAgentsMdStep } from './handoff-agents-md.js'
import { handoffClaudeStep } from './handoff-claude.js'
import { handoffCodexStep } from './handoff-codex.js'
import { handoffWizardStep } from './handoff-wizard.js'

/**
 * The complete set of handoff targets accepted by `--target`. Kept as a
 * runtime array (not just a type) so the CLI can validate user input
 * against the same source of truth that drives the picker.
 */
export const HANDOFF_CHOICES: readonly HandoffChoice[] = [
  'claude-code',
  'codex',
  'agents-md',
  'wizard',
] as const

/**
 * Validate a user-supplied `--target` value. Returns the canonical
 * `HandoffChoice` if valid, or `null` otherwise. `undefined` input
 * (flag absent) returns `null` too — callers distinguish absence from
 * invalidity before calling this.
 */
export function resolveTarget(target: string | undefined): HandoffChoice | null {
  if (!target) return null
  return (HANDOFF_CHOICES as readonly string[]).includes(target)
    ? (target as HandoffChoice)
    : null
}

/**
 * Pick the default option in the menu.
 *
 * Detected CLIs win — Claude Code first, then Codex. Otherwise we default to
 * the AGENTS.md path because that's the broadest "works without anything else
 * installed" option. The CipherStash Agent option is positioned as a fallback
 * (slow first run, requires the wizard package on top of the CLI) and is
 * never selected by default. The same defaulting applies in both `plan` and
 * `implement` modes; `mode` is plumbed in so future asymmetries can be added
 * without a wider refactor.
 */
export function defaultChoice(
  state: InitState,
  _mode: InitMode,
): HandoffChoice {
  if (state.agents?.cli.claudeCode) return 'claude-code'
  if (state.agents?.cli.codex) return 'codex'
  return 'agents-md'
}

/**
 * Build the option list for the menu. Hints reflect detection state, not
 * availability — a missing CLI doesn't hide the option (handoff steps
 * still write the rules files and print install instructions), it just
 * nudges the user toward what's already on PATH.
 */
export function buildOptions(
  state: InitState,
  _mode: InitMode,
): { value: HandoffChoice; label: string; hint?: string }[] {
  const claudeHint = state.agents?.cli.claudeCode
    ? 'claude detected — will launch interactively'
    : 'claude not on PATH — files will be written, install link shown'
  const codexHint = state.agents?.cli.codex
    ? 'codex detected — will launch interactively'
    : 'codex not on PATH — files will be written, install link shown'

  return [
    {
      value: 'claude-code',
      label: 'Hand off to Claude Code',
      hint: claudeHint,
    },
    {
      value: 'codex',
      label: 'Hand off to Codex',
      hint: codexHint,
    },
    {
      value: 'agents-md',
      label: 'Write AGENTS.md',
      hint: 'works with Cursor, Windsurf, Cline, and more',
    },
    {
      value: 'wizard',
      label: 'Use the CipherStash Agent',
      hint: 'our hosted setup wizard (runs `stash wizard`)',
    },
  ]
}

export const howToProceedStep: HandoffStep = {
  id: 'how-to-proceed',
  name: 'How to proceed',
  async run(state: InitState): Promise<InitState> {
    const mode: InitMode = state.mode ?? 'implement'

    // Caller pre-resolved the handoff target (e.g. via `--target` on the
    // CLI). Skip the interactive picker entirely so the command is safe
    // to run from automation / non-TTY contexts.
    let choice: HandoffChoice
    if (state.handoff) {
      choice = state.handoff
    } else {
      const message =
        mode === 'plan'
          ? 'Which agent should write the plan?'
          : 'How would you like to finish setup?'

      const picked = await p.select<HandoffChoice>({
        message,
        options: buildOptions(state, mode),
        initialValue: defaultChoice(state, mode),
      })

      if (p.isCancel(picked)) throw new CancelledError()
      choice = picked
    }

    const next: InitState = { ...state, handoff: choice }

    switch (choice) {
      case 'claude-code':
        return handoffClaudeStep.run(next)
      case 'codex':
        return handoffCodexStep.run(next)
      case 'agents-md':
        return handoffAgentsMdStep.run(next)
      case 'wizard':
        return handoffWizardStep.run(next)
    }
  },
}
