import * as p from '@clack/prompts'
import { CliExit } from '../../cli/exit.js'
import { isInteractive } from '../../config/tty.js'
import { messages } from '../../messages.js'
import { HANDOFF_CHOICES } from '../impl/steps/how-to-proceed.js'
import { planCommand } from '../plan/index.js'
import { createBaseProvider } from './providers/base.js'
import { createDrizzleProvider } from './providers/drizzle.js'
import { createPrismaNextProvider } from './providers/prisma-next.js'
import { createSupabaseProvider } from './providers/supabase.js'
import { authenticateStep } from './steps/authenticate.js'
import { buildSchemaStep } from './steps/build-schema.js'
import { gatherContextStep } from './steps/gather-context.js'
import { installDepsStep } from './steps/install-deps.js'
import { installEqlStep } from './steps/install-eql.js'
import { resolveDatabaseStep } from './steps/resolve-database.js'
import { resolveProxyChoiceStep } from './steps/resolve-proxy-choice.js'
import type { InitProvider, InitState } from './types.js'
import { CancelledError } from './types.js'
import { detectPackageManager, runnerCommand } from './utils.js'

const PROVIDER_MAP: Record<string, () => InitProvider> = {
  supabase: createSupabaseProvider,
  drizzle: createDrizzleProvider,
  'prisma-next': createPrismaNextProvider,
}

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
  authenticateStep,
  resolveDatabaseStep,
  resolveProxyChoiceStep,
  buildSchemaStep,
  installDepsStep,
  installEqlStep,
  gatherContextStep,
]

function resolveProvider(flags: Record<string, boolean>): InitProvider {
  // When multiple flags are set, use the first matching provider but
  // combine all flag names into the provider name for referrer tracking.
  const matchedKeys = Object.keys(PROVIDER_MAP).filter((key) => flags[key])

  if (matchedKeys.length === 0) {
    return createBaseProvider()
  }

  // Use the first matched provider for UX (intro message, connection options, etc.)
  // matchedKeys[0] is guaranteed by the length check above; the optional chain
  // is just to satisfy biome's no-non-null-assertion rule.
  const factory = PROVIDER_MAP[matchedKeys[0]]
  const provider = factory ? factory() : createBaseProvider()

  // Combine all matched flag names for the referrer
  if (matchedKeys.length > 1) {
    provider.name = matchedKeys.sort().join('-')
  }

  return provider
}

export async function initCommand(
  flags: Record<string, boolean>,
  values: Record<string, string> = {},
) {
  const provider = resolveProvider(flags)

  p.intro('CipherStash Stack Setup')
  p.log.info(provider.introMessage)

  let state: InitState = {}

  // Thread `--region <slug>` through to the authenticate step so init can run
  // non-interactively (STASH_REGION works even without this, via the env
  // fallback in resolveRegion).
  if (values.region) {
    state.regionFlag = values.region
  }

  // Parse --proxy and --no-proxy flags; --proxy wins if both are set
  if (flags.proxy) {
    state.usesProxy = true
  } else if (flags['no-proxy']) {
    state.usesProxy = false
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
      // The Drizzle flow (and Supabase `--migration` mode) GENERATES an EQL
      // migration rather than applying it — EQL isn't in the database until
      // the user runs the migration. That's the intended, honest end state
      // for these flows (applying is the ORM/migration tool's job), so it's
      // NOT an incomplete setup — but we must not claim "installed" either.
      const applyCmd =
        state.integration === 'supabase'
          ? 'supabase db push'
          : 'drizzle-kit migrate'
      checkmarks.push(
        `○ EQL migration generated — apply it with \`${applyCmd}\``,
      )
    }

    // EQL is required for encryption. Some integrations install it out-of-band
    // and legitimately leave `eqlInstalled` false here: Prisma Next installs it
    // via `migration apply`, and the Drizzle flow generates a migration the
    // user applies with `drizzle-kit migrate` (`eqlMigrationPending`). Only a
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
        await planCommand()
        return
      }
      p.outro(`Next: run \`${cli} plan\` to draft your encryption plan.`)
    } else {
      // Non-TTY users (CI, agent Bash tools, pipes) will hit the same
      // agent-target picker in `stash plan`, which only reads from
      // /dev/tty. Steer them at `--target` up front so the next command
      // doesn't surprise them.
      p.outro(
        `Next: run \`${cli} plan --target <${HANDOFF_CHOICES.join('|')}>\` to draft your encryption plan. The \`--target\` flag is required when running non-interactively (skips the agent-target picker).`,
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
