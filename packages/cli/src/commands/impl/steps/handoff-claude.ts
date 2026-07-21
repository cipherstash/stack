import * as p from '@clack/prompts'
import { spawnAgent, writeArtifacts } from '../../init/lib/handoff-helpers.js'
import { installSkills } from '../../init/lib/install-skills.js'
import {
  CONTEXT_REL_PATH,
  SETUP_PROMPT_REL_PATH,
} from '../../init/lib/write-context.js'
import type { HandoffStep, InitState } from '../../init/types.js'

const CLAUDE_SKILLS_DIR = '.claude/skills'

const CLAUDE_INSTALL_URL = 'https://code.claude.com/docs/en/quickstart'

/**
 * Hand off to Claude Code: copy the per-integration set of skills into
 * `.claude/skills/`, write `.cipherstash/context.json` and
 * `.cipherstash/setup-prompt.md`, then spawn `claude`. If `claude` is not
 * on PATH we still write the artifacts and print install + manual-launch
 * instructions.
 */
export const handoffClaudeStep: HandoffStep = {
  id: 'handoff-claude',
  name: 'Hand off to Claude Code',
  async run(state: InitState): Promise<InitState> {
    const cwd = process.cwd()
    const integration = state.integration ?? 'postgresql'

    const { copied, failed } = installSkills(
      cwd,
      CLAUDE_SKILLS_DIR,
      integration,
    )
    if (copied.length > 0) {
      p.log.success(
        `Installed ${copied.length} skill${copied.length !== 1 ? 's' : ''} into ${CLAUDE_SKILLS_DIR}/: ${copied.join(', ')}`,
      )
    }
    if (failed.length > 0) {
      // Unlike the Codex handoff there is no AGENTS.md on this path to
      // inline into, so the guidance is genuinely absent — say so rather
      // than letting the run look complete (#736 follow-up review).
      p.log.warn(
        `${failed.length} skill${failed.length !== 1 ? 's' : ''} could not be installed to ${CLAUDE_SKILLS_DIR}/: ${failed.join(', ')}. The agent will run without them — https://cipherstash.com/docs covers the same ground.`,
      )
    }

    writeArtifacts(cwd, state, 'claude-code', {
      installed: copied,
      inlined: [],
      failed,
    })

    const mode = state.mode ?? 'implement'
    // Only point the agent at the skills dir when skills were actually copied.
    // A stripped CLI build (no bundled skills) copies nothing — claiming
    // they're there would send the agent to read files that don't exist.
    const skillsClause =
      copied.length > 0
        ? `The installed skills under ${CLAUDE_SKILLS_DIR}/ have the rules; `
        : ''
    const launchPrompt =
      mode === 'plan'
        ? `Read ${SETUP_PROMPT_REL_PATH} and produce the planning deliverable it describes. ${skillsClause}${CONTEXT_REL_PATH} has the project facts. Do not edit code or run mutating commands during this phase.`
        : `Read ${SETUP_PROMPT_REL_PATH} and complete the setup steps. ${skillsClause}${CONTEXT_REL_PATH} has the project facts.`

    if (!state.agents?.cli.claudeCode) {
      p.note(
        [
          'Claude Code is not installed on this machine.',
          `Install: ${CLAUDE_INSTALL_URL}`,
          '',
          'Once installed, run:',
          `  claude --allow-dangerously-skip-permissions '${launchPrompt}'`,
        ].join('\n'),
        'Files written — install Claude Code to run the handoff',
      )
      return state
    }

    p.log.info('Launching Claude Code...')
    const exitCode = await spawnAgent('claude', launchPrompt)
    if (exitCode !== 0) {
      p.log.warn(
        `Claude Code exited with code ${exitCode}. Re-run \`claude --allow-dangerously-skip-permissions '${launchPrompt}'\` to resume.`,
      )
    }

    return state
  },
}
