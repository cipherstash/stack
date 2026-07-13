import { execSync } from 'node:child_process'
import * as p from '@clack/prompts'
import { isInteractive } from '../../../config/tty.js'
import type { InitProvider, InitState, InitStep } from '../types.js'
import { CancelledError } from '../types.js'
import {
  combinedInstallCommands,
  detectPackageManager,
  isPackageInstalled,
} from '../utils.js'

const STACK_PACKAGE = '@cipherstash/stack'
const CLI_PACKAGE = 'stash'
const PRISMA_NEXT_PACKAGE = '@cipherstash/prisma-next'
const DRIZZLE_PACKAGE = '@cipherstash/stack-drizzle'
const SUPABASE_PACKAGE = '@cipherstash/stack-supabase'

/**
 * The integration adapter is its OWN package (depends on `@cipherstash/stack`),
 * not a subpath of it — so whichever integration the user picked, its adapter
 * package must be installed too, or the scaffolded client code (which imports
 * e.g. `@cipherstash/stack-drizzle`) fails to resolve.
 */
function integrationPackageFor(integration?: string): string | null {
  switch (integration) {
    case 'prisma-next':
      return PRISMA_NEXT_PACKAGE
    case 'drizzle':
      return DRIZZLE_PACKAGE
    case 'supabase':
      return SUPABASE_PACKAGE
    default:
      return null
  }
}

/**
 * Install the runtime + dev npm packages the user needs to run encryption:
 *
 * - `@cipherstash/stack` (prod) — the encryption client, schema builders, and
 *   EQL v3 typed client.
 * - the integration adapter package (prod), if the chosen integration has one:
 *   `@cipherstash/stack-drizzle`, `@cipherstash/stack-supabase`, or
 *   `@cipherstash/prisma-next`. These are separate packages that depend on
 *   `@cipherstash/stack`.
 * - `stash` (dev) — the CLI itself, so the user can run `stash eql install`,
 *   `stash wizard`, etc. as a project script without the global install.
 *
 * Skips silently when everything is already present. Prompts before running the
 * install commands so the user sees the package manager invocation that's
 * about to execute.
 */
export const installDepsStep: InitStep = {
  id: 'install-deps',
  name: 'Install dependencies',
  async run(state: InitState, provider: InitProvider): Promise<InitState> {
    const integrationPkg =
      integrationPackageFor(state.integration) ??
      integrationPackageFor(provider.name)
    const stackPresent = isPackageInstalled(STACK_PACKAGE)
    const cliPresent = isPackageInstalled(CLI_PACKAGE)
    const integrationPresent = integrationPkg
      ? isPackageInstalled(integrationPkg)
      : true

    // Everything already there — silent success, no prompts.
    if (stackPresent && cliPresent && integrationPresent) {
      const installed = integrationPkg
        ? `${STACK_PACKAGE}, ${integrationPkg} and ${CLI_PACKAGE}`
        : `${STACK_PACKAGE} and ${CLI_PACKAGE}`
      p.log.success(`${installed} are already installed.`)
      return { ...state, stackInstalled: true, cliInstalled: true }
    }

    const pm = detectPackageManager()
    const prodPackages: string[] = []
    if (!stackPresent) prodPackages.push(STACK_PACKAGE)
    if (integrationPkg && !integrationPresent) prodPackages.push(integrationPkg)
    const devPackages = cliPresent ? [] : [CLI_PACKAGE]
    const commands = combinedInstallCommands(pm, prodPackages, devPackages)

    const missingList = [
      ...prodPackages.map((pkg) => `${pkg} (prod)`),
      ...devPackages.map((pkg) => `${pkg} (dev)`),
    ].join(', ')

    // Non-interactive (CI, agents, pipes): no TTY to answer, so install by
    // default and continue rather than abort. `stash init` is a setup command;
    // installing its own dependencies is the expected non-interactive default.
    if (!isInteractive()) {
      p.log.info(`Installing ${missingList} (non-interactive).`)
    }
    const install = isInteractive()
      ? await p.confirm({
          message: `Install ${missingList}? (${commands.join(' && ')})`,
          initialValue: true,
        })
      : true

    if (p.isCancel(install)) throw new CancelledError()

    if (!install) {
      p.log.info('Skipping package installation.')
      p.note(
        `You can install them manually later:\n  ${commands.join('\n  ')}`,
        'Manual Installation',
      )
      return {
        ...state,
        stackInstalled: stackPresent,
        cliInstalled: cliPresent,
      }
    }

    // Stream npm/pnpm/yarn output directly so the user sees progress.
    // Package installs can take tens of seconds and a silent spinner makes
    // the CLI look hung. We log a "starting" line here and a success line
    // after, letting the package manager own the terminal in between.
    const failed: string[] = []
    for (const cmd of commands) {
      p.log.step(`Running: ${cmd}`)
      try {
        execSync(cmd, { cwd: process.cwd(), stdio: 'inherit' })
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        p.log.error(`Install failed: ${cmd}`)
        p.log.error(message)
        failed.push(cmd)
      }
    }

    // Re-check from disk rather than inferring from exit codes — partial
    // success (one command works, the other fails) needs precise
    // per-package tracking, not a composite flag.
    const stackInstalled = isPackageInstalled(STACK_PACKAGE)
    const cliInstalled = isPackageInstalled(CLI_PACKAGE)
    const integrationInstalled = integrationPkg
      ? isPackageInstalled(integrationPkg)
      : true

    if (stackInstalled && cliInstalled && integrationInstalled) {
      p.log.success('Stack dependencies installed.')
    } else {
      const stillMissing = [
        ...(stackInstalled ? [] : [`${STACK_PACKAGE} (prod)`]),
        ...(integrationPkg && !integrationInstalled
          ? [`${integrationPkg} (prod)`]
          : []),
        ...(cliInstalled ? [] : [`${CLI_PACKAGE} (dev)`]),
      ]
      p.log.warn(`Still missing: ${stillMissing.join(', ')}.`)
      p.note(
        `You can retry manually:\n  ${(failed.length ? failed : commands).join('\n  ')}`,
        'Manual Installation',
      )
    }

    return { ...state, stackInstalled, cliInstalled }
  },
}
