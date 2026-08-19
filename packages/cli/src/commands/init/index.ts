import * as p from '@clack/prompts'
import { CliExit } from '../../cli/exit.js'
import { isInteractive } from '../../config/tty.js'
import { messages } from '../../messages.js'
import { HANDOFF_CHOICES, resolveTarget } from '../impl/steps/how-to-proceed.js'
import { planCommand } from '../plan/index.js'
import { createBaseProvider } from './providers/base.js'
import { createDrizzleProvider } from './providers/drizzle.js'
import { createPrismaProvider } from './providers/prisma.js'
import { createSupabaseProvider } from './providers/supabase.js'
import { authenticateStep } from './steps/authenticate.js'
import { buildSchemaStep } from './steps/build-schema.js'
import { gatherContextStep } from './steps/gather-context.js'
import { installDepsStep } from './steps/install-deps.js'
import { installEqlStep } from './steps/install-eql.js'
import { installSkillsStep } from './steps/install-skills.js'
import { resolveDatabaseStep } from './steps/resolve-database.js'
import type { InitProvider, InitState, ProviderKey } from './types.js'
import { CancelledError } from './types.js'
import { detectPackageManager, runnerCommand } from './utils.js'

/**
 * The integration flags and the provider each selects. Declaration order is the
 * tie-break for a multi-flag run: the first match supplies the UX (intro copy),
 * and `provider.selected` lists the matches in this order — so anything
 * iterating the selection is deterministic regardless of argv order.
 */
const PROVIDER_MAP: Record<ProviderKey, () => InitProvider> = {
  supabase: createSupabaseProvider,
  drizzle: createDrizzleProvider,
  prisma: createPrismaProvider,
}

/** Derived from the map rather than written out again: a hand-maintained copy
 * would let a new provider be added in one place only, and the flag would then
 * silently do nothing. */
const PROVIDER_KEYS = Object.keys(PROVIDER_MAP) as ProviderKey[]

/**
 * `stash init` does scaffold-once work only: auth, database connection,
 * schema introspection, dep install, EQL install, context gathering. It
 * exits at a clean checkpoint. The agent handoff (plan-or-implement) is
 * the responsibility of `stash impl`, which reads `.cipherstash/context.json`
 * and dispatches to the right handoff target.
 *
 * Splitting these gives the user a save-point between bootstrap and
 * implementation — they can review what init produced before committing
 * to the longer agent-driven phase.
 */
const STEPS = [
  // `install-skills` runs FIRST, and deliberately. It is the only step that
  // needs neither network, credentials, nor a database, and the guidance it
  // writes is what an agent needs most when a LATER step fails — auth, the
  // database URL and EQL all exit non-zero, and `stash-cli` is the skill that
  // covers recovering from each. Ordering it last is how #923 happened: the
  // only callers of `installSkills` were the handoff steps, which `stash init`
  // never reaches, so init shipped zero skills for an entire release.
  // Guarded by `__tests__/steps-wiring.test.ts` — a unit test of the step
  // alone would not have caught a pipeline that stopped calling it.
  installSkillsStep,
  authenticateStep,
  resolveDatabaseStep,
  buildSchemaStep,
  installDepsStep,
  installEqlStep,
  gatherContextStep,
]

/**
 * Turn the integration flags into the provider the pipeline threads through
 * every step.
 *
 * The flags are NOT mutually exclusive — `stash init --drizzle --supabase` is a
 * real invocation (a Drizzle project on Supabase), and nothing upstream rejects
 * it. Two separate things fall out of that, and conflating them was the bug:
 *
 * - `name` is the REFERRER. A multi-flag run joins every matched flag
 *   alphabetically, matching what `stash auth login --drizzle --supabase`
 *   records, and `authenticateStep` passes it to `login()`.
 * - `selected` is the CAPABILITY SIGNAL. Because the combined name equals no
 *   single flag, every `provider.name === 'supabase'` test in the pipeline went
 *   false on a combined run: init installed EQL directly instead of writing a
 *   migration, skipped the Supabase grants, skipped the Prisma branch, and
 *   installed no adapter package. Steps read this list instead, so the two
 *   concerns can't drift back together.
 */
function resolveProvider(flags: Record<string, boolean>): InitProvider {
  const matchedKeys = PROVIDER_KEYS.filter((key) => flags[key])

  if (matchedKeys.length === 0) {
    return createBaseProvider()
  }

  // The first matched provider supplies the UX (intro message).
  // matchedKeys[0] is guaranteed by the length check above; the optional chain
  // is just to satisfy biome's no-non-null-assertion rule.
  const factory = PROVIDER_MAP[matchedKeys[0]]
  const provider = factory ? factory() : createBaseProvider()

  provider.selected = matchedKeys
  // Combine all matched flag names for the referrer. Sorted on a COPY: sorting
  // `matchedKeys` in place would reorder `selected` too, now that it is the
  // same array.
  if (matchedKeys.length > 1) {
    provider.name = [...matchedKeys].sort().join('-')
  }

  return provider
}

export async function initCommand(
  flags: Record<string, boolean>,
  values: Record<string, string> = {},
) {
  const retiredProxyFlag = ['proxy', 'no-proxy'].find(
    (name) => flags[name] === true || Object.hasOwn(values, name),
  )
  if (retiredProxyFlag) {
    p.log.error(
      `\`--${retiredProxyFlag}\` has been removed. EQL v3 stores query configuration in column domains and does not use CipherStash Proxy; remove this flag and select only the project integration (for example, \`--supabase\` or \`--drizzle\`).`,
    )
    throw new CliExit(1)
  }

  // `--prisma-next` was renamed to `--prisma` for consistency with `--supabase`
  // and `--drizzle`. It selects the same Prisma Next setup flow; error rather
  // than silently ignore a previously-documented flag.
  if (flags['prisma-next'] === true || Object.hasOwn(values, 'prisma-next')) {
    p.log.error(
      '`--prisma-next` has been renamed to `--prisma`. Re-run `stash init --prisma` — it selects the same Prisma Next setup flow.',
    )
    throw new CliExit(1)
  }

  const provider = resolveProvider(flags)

  // `--target` on `init` selects the SKILLS DESTINATION and nothing else — it
  // does not perform a handoff the way `plan --target` / `impl --target` do.
  // Validated against the same `HANDOFF_CHOICES` so the three commands never
  // drift on what a target name means. Absent means "auto-detect".
  const targetFlag = values.target
  const target = resolveTarget(targetFlag)
  if (targetFlag && !target) {
    p.log.error(
      `Unknown --target \`${targetFlag}\`. Valid values: ${HANDOFF_CHOICES.join(', ')}.`,
    )
    throw new CliExit(1)
  }

  p.intro('CipherStash Stack Setup')
  p.log.info(provider.introMessage)

  let state: InitState = {}
  if (target) state.targetFlag = target

  // Thread `--region <slug>` through to the authenticate step so init can run
  // non-interactively (STASH_REGION works even without this, via the env
  // fallback in resolveRegion).
  if (values.region) {
    state.regionFlag = values.region
  }

  try {
    for (const step of STEPS) {
      state = await step.run(state, provider)
    }

    const pm = detectPackageManager()
    const cli = runnerCommand(pm, 'stash')
    // Only claim what actually happened. Auth throws on failure (reaching here
    // means it succeeded); the database step *resolves* a URL but never opens a
    // connection, so don't claim "verified"; the client scaffold is skipped for
    // Prisma Next (no `clientFilePath` on state). `schemaGenerated` is true only
    // when a placeholder was actually written — when an existing client file is
    // kept, `clientFilePath` is still set but nothing was scaffolded, so don't
    // claim we did.
    const checkmarks: string[] = [
      '✓ Authenticated to CipherStash',
      '✓ Database URL resolved',
    ]
    if (state.schemaGenerated) {
      checkmarks.push('✓ Encryption client scaffolded')
    } else if (state.clientFilePath) {
      checkmarks.push('✓ Encryption client kept (existing file)')
    }
    if (state.stackInstalled) {
      checkmarks.push('✓ `@cipherstash/stack` installed')
    }
    if (state.cliInstalled) checkmarks.push('✓ `stash` CLI installed')
    if (state.eqlInstalled) {
      checkmarks.push('✓ EQL extension installed')
    } else if (state.eqlMigrationPending) {
      // The Drizzle and Supabase flows GENERATE an EQL migration rather than
      // applying it — EQL isn't in the database until the user runs the
      // migration. That's the intended, honest end state for these flows
      // (applying is the migration tool's job), so it's NOT an incomplete
      // setup — but we must not claim "installed" either.
      //
      // Match on BOTH signals, exactly as `installEqlStep` routes. `integration`
      // alone is wrong: `detectIntegration` reads it from the DATABASE_URL host,
      // and a local Supabase stack is `127.0.0.1:54322` — so integration lands on
      // 'postgresql' while the provider is 'supabase', and this printed
      // `drizzle-kit migrate` at the very user the Supabase route targets.
      // Drizzle wins when both fire: it owns the migration history there, and
      // `--supabase` is only the grants modifier.
      //
      // The flag half reads `provider.selected`, never `provider.name` — a
      // combined `--drizzle --supabase` run names itself 'drizzle-supabase',
      // which is neither, so both halves went false and the apply step fell
      // through to the drizzle-kit default with no reasoning behind it.
      const isDrizzle =
        state.integration === 'drizzle' || provider.selected.includes('drizzle')
      const isSupabase =
        state.integration === 'supabase' ||
        provider.selected.includes('supabase')
      const applyStep =
        isSupabase && !isDrizzle
          ? 'apply it with `supabase db reset` (local) or `supabase db push` (remote)'
          : 'apply it with `drizzle-kit migrate`'
      // `eqlMigrationPending` covers two different runs that need the same
      // apply guidance: the migration this run wrote, and one an earlier run
      // (or a standalone `stash eql migration --supabase`) already left on
      // disk. Only the verb differs — saying "generated" over the second is a
      // claim about work this run did not do, and the user can disprove it
      // from their own diff. `eqlMigrationAlreadyPresent` is deliberately not
      // consulted by the `eqlPending` check below: either way a migration
      // exists and the setup is complete.
      const verb = state.eqlMigrationAlreadyPresent
        ? 'already present'
        : 'generated'
      checkmarks.push(`○ EQL migration ${verb} — ${applyStep}`)
    }

    // Report the skills outcome in the summary, both ways. A silent
    // `installedSkills: []` is what let #923 hide for a release: init printed
    // success, the context file looked plausible, and the agent driving the
    // setup was never told the guidance it needed was sitting unread in
    // `node_modules`. Absent skills are degraded guidance, not a broken
    // setup, so this never changes the exit code — unlike `eqlPending` below.
    //
    // Pushed BEFORE the EQL check so it appears on the failing summary too.
    // That run is the one where it matters most: the agent is about to be
    // told setup is incomplete, and `stash-cli` is the skill that covers
    // `stash eql install`.
    const installedSkills = state.skills?.installed ?? []
    if (installedSkills.length > 0) {
      checkmarks.push(
        `✓ ${installedSkills.length} agent skill${installedSkills.length !== 1 ? 's' : ''} installed`,
      )
    } else {
      const suggestion = state.targetFlag ?? 'claude-code'
      checkmarks.push(
        `○ No agent skills installed — no coding agent detected. Run \`${cli} plan --target ${suggestion}\` to install them.`,
      )
    }

    // EQL is required for encryption. Some integrations install it out-of-band
    // and legitimately leave `eqlInstalled` false here: Prisma Next installs it
    // via `prisma-next migrate`, and the Drizzle and Supabase flows generate a
    // migration the user applies themselves (`eqlMigrationPending`). Only a
    // run that neither installed EQL nor generated a migration to install it is
    // genuinely incomplete — say so and exit non-zero so automation can't read
    // a false success from a run where encryption would fail at query time.
    const eqlPending =
      !state.eqlInstalled &&
      !state.eqlMigrationPending &&
      state.integration !== 'prisma-next'
    if (eqlPending) {
      checkmarks.push('✗ EQL extension NOT installed')
      p.note(checkmarks.join('\n'), messages.init.setupIncomplete)
      p.log.error(
        `${messages.init.eqlNotInstalled} Run \`${cli} eql install\` before running any encryption.`,
      )
      throw new CliExit(1)
    }

    p.note(checkmarks.join('\n'), 'Setup complete')

    // Offer to chain straight into `stash plan` so first-time users don't
    // have to copy/paste the next command. Default-yes for low friction;
    // answering N (or running non-interactively) preserves the explicit
    // multi-command flow. Drafting a plan is fast (~1–3 min of agent
    // thinking) and produces a reviewable artifact — `stash impl` is the
    // separate, slower verb that actually mutates code.
    //
    // Gated on the shared `isInteractive()` (config/tty.ts), the same helper
    // every other prompt uses. `process.stdout.isTTY` was wrong on both
    // counts: it ignored CI entirely (a runner with an allocated TTY blocked
    // here forever, since clack `confirm` reads /dev/tty), and it asked about
    // the wrong stream — a redirected stdin still hangs the prompt.
    if (isInteractive()) {
      const proceed = await p.confirm({
        message: `Continue to \`${cli} plan\` now to draft your encryption plan?`,
        initialValue: true,
      })
      if (!p.isCancel(proceed) && proceed) {
        p.outro('Setup complete — handing off to `stash plan`.')
        // Forward an explicit `--target`: the user already named their agent
        // once, so re-asking with the picker would be asking the same
        // question twice. Without the flag, `plan` prompts as before.
        await planCommand({}, target ? { target } : {})
        return
      }
      p.outro(`Next: run \`${cli} plan\` to draft your encryption plan.`)
    } else {
      // Non-TTY users (CI, agent Bash tools, pipes) will hit the same
      // agent-target picker in `stash plan`, which only reads from
      // /dev/tty. Steer them at `--target` up front so the next command
      // doesn't surprise them.
      p.outro(
        target
          ? `Next: run \`${cli} plan --target ${target}\` to draft your encryption plan.`
          : `Next: run \`${cli} plan --target <${HANDOFF_CHOICES.join('|')}>\` to draft your encryption plan. The \`--target\` flag is required when running non-interactively (skips the agent-target picker).`,
      )
    }
  } catch (err) {
    if (err instanceof CancelledError) {
      p.cancel('Setup cancelled.')
      // Cooperative exit: unwinds to run() so the cancel is tracked and the
      // telemetry flush completes before the process exits 0 (see cli/exit.ts).
      throw new CliExit(0)
    }
    throw err
  }
}
