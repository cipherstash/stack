import { execSync } from 'node:child_process'
import * as p from '@clack/prompts'
import { isInteractive } from '../../../config/tty.js'
import { expectedVersion, pinnedSpec } from '../../../runtime-versions.js'
import type { InitProvider, InitState, InitStep } from '../types.js'
import { CancelledError } from '../types.js'
import {
  combinedInstallCommands,
  detectPackageManager,
  installedVersion,
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
 * Report packages whose installed (resolved, on-disk) version differs from
 * the version this CLI release was built alongside. Skew like this is how the
 * dist-tag failure mode (#661) stays invisible: the project's `^`-range spec
 * looks fine while `node_modules` holds a stale `0.19.0` or placeholder
 * `0.0.0`. Packages that are absent, or absent from the release map (source
 * builds), report nothing.
 */
export function versionSkew(
  packages: readonly string[],
  versions?: Readonly<Record<string, string>>,
): Array<{ pkg: string; installed: string; expected: string }> {
  const skewed: Array<{ pkg: string; installed: string; expected: string }> = []
  for (const pkg of packages) {
    const expected = versions ? versions[pkg] : expectedVersion(pkg)
    if (!expected) continue
    const installed = installedVersion(pkg)
    if (installed && installed !== expected)
      skewed.push({ pkg, installed, expected })
  }
  return skewed
}

/** Warn (never mutate) when installed versions don't match this release. */
function warnOnVersionSkew(packages: readonly string[]): void {
  const skewed = versionSkew(packages)
  if (skewed.length === 0) return
  const pm = detectPackageManager()
  const lines = skewed.map(
    ({ pkg, installed, expected }) =>
      `${pkg}: installed ${installed}, this release of stash expects ${expected}`,
  )
  p.log.warn(`Version skew detected:\n  ${lines.join('\n  ')}`)
  p.note(
    `Align them with:\n  ${combinedInstallCommands(
      pm,
      skewed.map(({ pkg }) => pinnedSpec(pkg)),
      [],
    ).join('\n  ')}`,
    'Version skew',
  )
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
 * Installs are PINNED to the versions this CLI release was built alongside
 * (see `src/runtime-versions.ts` and #661) — bare package names resolve
 * through npm dist-tags, which lag or point at placeholders during
 * pre-release windows and then deliver a different release than the CLI
 * driving the setup. Already-present packages are left untouched, but a
 * version that differs from this release's is called out loudly.
 *
 * Skips silently when everything is already present at matching versions.
 * Prompts before running the install commands so the user sees the package
 * manager invocation that's about to execute.
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

    const allPackages = [
      STACK_PACKAGE,
      ...(integrationPkg ? [integrationPkg] : []),
      CLI_PACKAGE,
    ]

    // Everything already there — leave it alone (no prompts), but surface
    // version skew against this release rather than silently proceeding on a
    // stale or placeholder install (#661).
    if (stackPresent && cliPresent && integrationPresent) {
      const installed = integrationPkg
        ? `${STACK_PACKAGE}, ${integrationPkg} and ${CLI_PACKAGE}`
        : `${STACK_PACKAGE} and ${CLI_PACKAGE}`
      p.log.success(`${installed} are already installed.`)
      warnOnVersionSkew(allPackages)
      return { ...state, stackInstalled: true, cliInstalled: true }
    }

    const pm = detectPackageManager()
    const prodPackages: string[] = []
    if (!stackPresent) prodPackages.push(pinnedSpec(STACK_PACKAGE))
    if (integrationPkg && !integrationPresent)
      prodPackages.push(pinnedSpec(integrationPkg))
    const devPackages = cliPresent ? [] : [pinnedSpec(CLI_PACKAGE)]
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
      // Fresh installs above are pinned, but packages that were ALREADY
      // present were not touched — check the whole set for skew.
      warnOnVersionSkew(allPackages)
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
