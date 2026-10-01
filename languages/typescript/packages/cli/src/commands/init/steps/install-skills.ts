import * as p from '@clack/prompts'
import { detectDrizzle, detectPrismaNext } from '../../db/detect.js'
import { type AgentEnvironment, detectAgents } from '../detect-agents.js'
import { installSkills } from '../lib/install-skills.js'
import type {
  HandoffChoice,
  InitProvider,
  InitState,
  InitStep,
  Integration,
  SkillsDelivery,
} from '../types.js'
import { mergeSkillsDelivery } from '../types.js'

export const CLAUDE_SKILLS_DIR = '.claude/skills'
export const CODEX_SKILLS_DIR = '.codex/skills'

/**
 * Which skills directories this run should write, in install order.
 *
 * An explicit `--target` wins outright — it is the user saying which agent
 * they are setting up for, and detection must not add a second directory
 * they did not ask for. The three non-directory targets (`agents-md`,
 * `lovable`, `wizard`) deliberately return nothing: those handoffs inline
 * skill bodies into AGENTS.md (or, for the wizard, install their own), and
 * `stash init` performs no handoff, so there is nothing here for it to write.
 *
 * Without a flag, both CLIs are honoured independently — a machine with
 * `claude` and `codex` both on PATH gets both, because either might be the
 * one that picks the project up. Project-level artifacts count as evidence
 * alongside the CLI: an agent running inside a repo that already has
 * `.claude/` is the exact flow #923 is about, and it does not require the
 * binary to be on the PATH this process inherited.
 */
export function skillDestinations(
  agents: AgentEnvironment,
  target: HandoffChoice | undefined,
): string[] {
  if (target === 'claude-code') return [CLAUDE_SKILLS_DIR]
  if (target === 'codex') return [CODEX_SKILLS_DIR]
  if (target !== undefined) return []

  const dests: string[] = []
  if (agents.cli.claudeCode || agents.project.claudeDir) {
    dests.push(CLAUDE_SKILLS_DIR)
  }
  if (agents.cli.codex || agents.project.codexDir) {
    dests.push(CODEX_SKILLS_DIR)
  }
  return dests
}

/**
 * Best guess at the integration BEFORE `resolve-database` and `build-schema`
 * have run, used only to pick a skill set.
 *
 * Returns `undefined` rather than guessing when nothing is conclusive, so
 * the caller falls back to `BASE_SKILLS` instead of shipping a wrong
 * integration's skills.
 *
 * The cwd signals and their precedence come from `build-schema`'s
 * `detectIntegration`, minus the one it cannot answer yet: `detectSupabase`
 * reads the resolved `DATABASE_URL`, which does not exist this early. On top
 * of those, the `--drizzle` and `--supabase` FLAGS count as conclusive here,
 * which `detectIntegration` does not do — it consults only `--prisma`. That
 * asymmetry is right for the encryption client (a project with no Drizzle
 * config should not get a Drizzle-shaped one just because a flag was passed)
 * and wrong for skills: a user who typed `--drizzle` is telling us which
 * integration to teach the agent about, and answering `undefined` here hands
 * them the base six instead of the Drizzle seven.
 *
 * Drizzle outranks Supabase on a combined `--drizzle --supabase` run, the
 * same way it does when init routes the EQL migration — it owns the
 * migration history there, and `--supabase` is the grants modifier.
 *
 * A bare `stash init` against a Supabase-hosted URL still falls through to
 * `undefined` and is corrected by the top-up in `build-schema`.
 *
 * Reads `provider.selected`, never `provider.name`: a combined
 * `--prisma --supabase` run names itself `'prisma-supabase'`, which equals
 * no single flag.
 */
export function guessIntegration(
  cwd: string,
  provider: InitProvider,
): Integration | undefined {
  if (provider.selected.includes('prisma')) return 'prisma-next'
  if (detectPrismaNext(cwd)) return 'prisma-next'
  if (detectDrizzle(cwd) || provider.selected.includes('drizzle')) {
    return 'drizzle'
  }
  if (provider.selected.includes('supabase')) return 'supabase'
  return undefined
}

/**
 * Copy the agent skills into the project — the FIRST thing `stash init` does.
 *
 * Ordering is the whole point of this step. `installSkills` needs no network,
 * no credentials and no database; every other init step needs at least one of
 * those and can fail. Running last (as the handoff steps effectively did) meant
 * a run that died at auth, at the database URL, or at EQL delivered no guidance
 * at all — and those failures are precisely when an agent needs `stash-cli`.
 * Running first, the skills survive any later exit, including Ctrl+C.
 *
 * Never fatal: `installSkills` degrades every filesystem error to a warning
 * (#736), and a run with no agent to install for is a normal outcome, not an
 * error. The init summary reports whichever happened — a silent
 * `installedSkills: []` is what made #923 invisible for a whole release.
 */
export const installSkillsStep: InitStep = {
  id: 'install-skills',
  name: 'Install agent skills',
  async run(state: InitState, provider: InitProvider): Promise<InitState> {
    const cwd = process.cwd()
    const agents = detectAgents(cwd, process.env)
    const integration = guessIntegration(cwd, provider)
    const dests = skillDestinations(agents, state.targetFlag)

    let skills: SkillsDelivery = { installed: [], inlined: [], failed: [] }
    for (const dest of dests) {
      const { copied, failed } = installSkills(cwd, dest, integration)
      if (copied.length > 0) {
        p.log.success(
          `Installed ${copied.length} skill${copied.length !== 1 ? 's' : ''} into ${dest}/: ${copied.join(', ')}`,
        )
      }
      if (failed.length > 0) {
        p.log.warn(
          `${failed.length} skill${failed.length !== 1 ? 's' : ''} could not be installed to ${dest}/: ${failed.join(', ')}.`,
        )
      }
      skills = mergeSkillsDelivery(skills, {
        installed: copied,
        inlined: [],
        failed,
      })
    }

    // `agents` is stored for `gather-context` (and the handoff steps, when
    // `plan`/`impl` reuse this state) so the PATH walk happens once per run.
    return { ...state, agents, skills }
  },
}

/**
 * Top up the installed skills once `build-schema` has resolved the real
 * integration.
 *
 * Only does anything for a run the first-step install could not classify —
 * in practice a bare `stash init` whose Supabase-ness lives in the
 * `DATABASE_URL` host. `installSkills` is idempotent (`cpSync` with
 * `force`), the per-integration set is a superset of `BASE_SKILLS`, and the
 * destinations are re-derived from the same inputs, so a re-run of the same
 * classification copies the same files again and reports the same names.
 *
 * Silent on success: the first step already announced the install, and a
 * second "installed N skills" line for four extra files reads like the work
 * happened twice.
 */
export function topUpSkills(
  cwd: string,
  state: InitState,
  integration: Integration,
): SkillsDelivery | undefined {
  if (!state.agents) return state.skills
  const dests = skillDestinations(state.agents, state.targetFlag)
  if (dests.length === 0) return state.skills

  let skills = state.skills
  for (const dest of dests) {
    const { copied, failed } = installSkills(cwd, dest, integration)
    skills = mergeSkillsDelivery(skills, {
      installed: copied,
      inlined: [],
      failed,
    })
  }
  return skills
}
