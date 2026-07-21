import * as p from '@clack/prompts'
import { buildAgentsMdBody } from '../../init/lib/build-agents-md.js'
import {
  AGENTS_MD_REL_PATH,
  writeAgentsMd,
  writeArtifacts,
} from '../../init/lib/handoff-helpers.js'
import { availableSkills } from '../../init/lib/install-skills.js'
import {
  CONTEXT_REL_PATH,
  SETUP_PROMPT_REL_PATH,
} from '../../init/lib/write-context.js'
import type { HandoffStep, InitState } from '../../init/types.js'

/**
 * Write `AGENTS.md`, `.cipherstash/context.json`, and
 * `.cipherstash/setup-prompt.md`, then stop.
 *
 * For users running editor-based agents (Cursor, Windsurf, Cline) or any
 * tool that follows the AGENTS.md convention but does NOT auto-load skill
 * directories. We inline the relevant skill content into AGENTS.md so the
 * agent has the API details right there.
 *
 * No `.codex/skills/` or `.claude/skills/` directory is written — those
 * tools wouldn't know to look there. Re-runs replace only the sentinel
 * region in AGENTS.md.
 */
export const handoffAgentsMdStep: HandoffStep = {
  id: 'handoff-agents-md',
  name: 'Write AGENTS.md',
  async run(state: InitState): Promise<InitState> {
    const cwd = process.cwd()
    const integration = state.integration ?? 'postgresql'

    const inlinable = availableSkills(integration)
    const managed = buildAgentsMdBody(
      integration,
      'doctrine-plus-skills',
      inlinable,
    )
    const written = writeAgentsMd(cwd, managed)

    writeArtifacts(cwd, state, 'agents-md', {
      installed: [],
      inlined: written ? inlinable : [],
      failed: written ? [] : inlinable,
    })

    p.note(
      [
        `Rules at ${AGENTS_MD_REL_PATH}`,
        `Action plan at ${SETUP_PROMPT_REL_PATH}`,
        `Context at ${CONTEXT_REL_PATH}`,
        '',
        'Cursor / Windsurf / Cline pick up AGENTS.md automatically.',
        `Open your agent and point it at ${SETUP_PROMPT_REL_PATH} to start.`,
      ].join('\n'),
      'Drive your editor agent',
    )

    return state
  },
}
