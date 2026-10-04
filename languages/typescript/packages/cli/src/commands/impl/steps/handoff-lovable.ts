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
 * `.cipherstash/setup-prompt.md` for a Lovable project, then stop.
 *
 * Same artifacts as the AGENTS.md handoff — Lovable's agent runs in
 * Lovable's cloud, not on this machine, so there is nothing to launch.
 * What differs is how the files reach the agent: Lovable only sees the
 * repo through its GitHub sync, so the guidance tells the user to commit
 * and push, then add a Knowledge pointer in the Lovable project settings.
 * That pointer matters because Lovable does not auto-load AGENTS.md the
 * way Cursor/Windsurf do — without it the agent answers CipherStash
 * questions from stale training data (the pre-EQL-v3 "needs a Postgres
 * extension and superuser" story) instead of the inlined skills.
 */
export const handoffLovableStep: HandoffStep = {
  id: 'handoff-lovable',
  name: 'Write AGENTS.md for Lovable',
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

    writeArtifacts(cwd, state, 'lovable', {
      installed: [],
      inlined: written ? inlinable : [],
      failed: written ? [] : inlinable,
    })

    // The note must reflect what was actually written: telling the user to
    // commit an AGENTS.md that failed to write sends them hunting for a
    // file that does not exist (writeAgentsMd already logged the warning).
    p.note(
      written
        ? [
            `Rules at ${AGENTS_MD_REL_PATH}`,
            `Action plan at ${SETUP_PROMPT_REL_PATH}`,
            `Context at ${CONTEXT_REL_PATH}`,
            '',
            'Lovable only sees these files through its GitHub sync:',
            `1. Commit and push ${AGENTS_MD_REL_PATH} and .cipherstash/`,
            '2. In Lovable: Settings → Knowledge, add:',
            `   "Follow ${AGENTS_MD_REL_PATH} for all CipherStash work.`,
            `   Start from ${SETUP_PROMPT_REL_PATH}."`,
            `3. Ask the Lovable agent to read ${SETUP_PROMPT_REL_PATH} and begin.`,
          ].join('\n')
        : [
            `${AGENTS_MD_REL_PATH} could not be written (see the warning above).`,
            `Action plan at ${SETUP_PROMPT_REL_PATH}`,
            `Context at ${CONTEXT_REL_PATH}`,
            '',
            'Fix the file permissions and re-run this command so the rules',
            `land in ${AGENTS_MD_REL_PATH}, then commit, push, and add the`,
            'Knowledge pointer in Lovable (Settings → Knowledge).',
          ].join('\n'),
      'Drive the Lovable agent',
    )

    return state
  },
}
