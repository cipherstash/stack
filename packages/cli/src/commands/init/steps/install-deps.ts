import { execSync } from 'node:child_process'
import * as p from '@clack/prompts'
import { isInteractive } from '../../../config/tty.js'
import {
  compareVersions,
  expectedVersion,
  pinnedSpec,
  RUNTIME_PACKAGE_VERSIONS,
} from '../../../runtime-versions.js'
import type { InitProvider, InitState, InitStep } from '../types.js'
import { CancelledError } from '../types.js'
import {
  combinedInstallCommands,
  detectPackageManager,
  devInstallCommand,
  installedVersion,
  isPackageInstalled,
} from '../utils.js'

const STACK_PACKAGE = '@cipherstash/stack'
const CLI_PACKAGE = 'stash'

/**
 * The integration adapter is its OWN package (depends on `@cipherstash/stack`),
 * not a subpath of it — so whichever integration the user picked, its adapter
 * package must be installed too, or the scaffolded client code (which imports
 * e.g. `@cipherstash/stack-drizzle`) fails to resolve.
 *
 * Exported so a unit test can assert every adapter is a key of
 * `RELEASE_TRAIN_MANIFESTS` (`src/release-train.ts`) — an adapter added here
 * but not to the release train would install unpinned and be invisible to the
 * skew warning, silently reintroducing #661 for exactly the newest package.
 */
export const INTEGRATION_ADAPTER_PACKAGES: Readonly<Record<string, string>> = {
  'prisma-next': '@cipherstash/prisma-next',
  drizzle: '@cipherstash/stack-drizzle',
  supabase: '@cipherstash/stack-supabase',
}

function integrationPackageFor(integration?: string): string | null {
  if (!integration) return null
  return INTEGRATION_ADAPTER_PACKAGES[integration] ?? null
}

/** Sentinel shown when a package directory exists but its manifest can't be
 * read — a broken state worth surfacing, not skipping (aborted installs leave
 * exactly this behind). */
const UNREADABLE_VERSION = 'unknown (unreadable package.json)'

export type VersionSkewEntry = {
  pkg: string
  installed: string
  expected: string
  /** `behind`: older than this release (or unreadable) — offer alignment.
   * `ahead`: NEWER than this release expects — the install is likely fine
   * and the fix is updating stash, never downgrading the package. */
  direction: 'behind' | 'ahead'
}

/**
 * Report packages whose installed (resolved, on-disk) version differs from
 * the version this CLI release was built alongside. Skew like this is how the
 * dist-tag failure mode (#661) stays invisible: the project's `^`-range spec
 * looks fine while `node_modules` holds a stale `0.19.0` or placeholder
 * `0.0.0`. A package that is present but has an unreadable manifest is
 * reported too (as {@link UNREADABLE_VERSION}) — that is a broken install,
 * not a matching one. Packages that are absent, or absent from the release
 * map (source builds), report nothing.
 */
export function versionSkew(
  packages: readonly string[],
  versions: Readonly<Record<string, string>> = RUNTIME_PACKAGE_VERSIONS,
): VersionSkewEntry[] {
  const skewed: VersionSkewEntry[] = []
  for (const pkg of packages) {
    const expected = expectedVersion(pkg, versions)
    if (!expected) continue
    if (!isPackageInstalled(pkg)) continue
    const installed = installedVersion(pkg) ?? UNREADABLE_VERSION
    if (installed === expected) continue
    // Unreadable manifests are treated as `behind`: a broken install should
    // be offered the (re)install fix, not a stash upgrade.
    const direction =
      installed !== UNREADABLE_VERSION &&
      compareVersions(installed, expected) > 0
        ? ('ahead' as const)
        : ('behind' as const)
    skewed.push({ pkg, installed, expected, direction })
  }
  return skewed
}

/** Render one `pkg: installed X, this release of stash expects Y` line per
 * skewed package. */
function skewLines(skewed: readonly VersionSkewEntry[]): string {
  return skewed
    .map(
      ({ pkg, installed, expected }) =>
        `${pkg}: installed ${installed}, this release of stash expects ${expected}`,
    )
    .join('\n  ')
}

/** Render the newer-than-expected lines: the fix is updating stash, never
 * downgrading a runtime package past releases the project already uses. */
function aheadLines(ahead: readonly VersionSkewEntry[]): string {
  return ahead
    .map(
      ({ pkg, installed, expected }) =>
        `${pkg}: installed ${installed} is newer than this release of stash expects (${expected})`,
    )
    .join('\n  ')
}

/** Split pinned install specs into (prod, dev) lists — `stash` is a dev
 * dependency by init's own convention; everything else is prod. */
function splitProdDev(packages: readonly string[]): {
  prod: string[]
  dev: string[]
} {
  const prod: string[] = []
  const dev: string[] = []
  for (const pkg of packages) {
    ;(pkg === CLI_PACKAGE ? dev : prod).push(pinnedSpec(pkg))
  }
  return { prod, dev }
}

/**
 * Install the runtime + dev npm packages the user needs to run encryption:
 *
 * - `@cipherstash/stack` (prod) — the encryption client, schema builders, and
 *   EQL v3 typed client.
 * - the integration adapter package (prod), if the chosen integration has one
 *   (see {@link INTEGRATION_ADAPTER_PACKAGES}).
 * - `stash` (dev) — the CLI itself, so the user can run `stash eql install`,
 *   `stash wizard`, etc. as a project script without the global install.
 *
 * Installs are PINNED to the versions this CLI release was built alongside
 * (see `src/runtime-versions.ts` and #661) — bare package names resolve
 * through npm dist-tags, which lag or point at placeholders during
 * pre-release windows and then deliver a different release than the CLI
 * driving the setup.
 *
 * Version skew on ALREADY-INSTALLED packages is surfaced unconditionally,
 * before any prompt or early exit, so no path (decline, partial failure,
 * everything-already-present) proceeds silently on a stale or placeholder
 * install. Interactively, init offers to align the skewed packages to this
 * release in the same confirm as the missing installs; non-interactively it
 * NEVER mutates an existing install — it warns, prints the exact align
 * commands, and proceeds.
 *
 * When everything is already present at matching versions this logs a
 * success line and moves on with no prompts.
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

    // Surface skew FIRST and unconditionally — before any prompt, decline,
    // failure, or early return can skip it (#661). Every path below inherits
    // this warning.
    const pm = detectPackageManager()
    const allSkew = versionSkew(allPackages)
    // Direction matters (#666 review): only packages BEHIND this release get
    // the align treatment. A package AHEAD of this release means the CLI is
    // the stale side — advising a downgrade would walk the project back past
    // releases it already depends on.
    const skewed = allSkew.filter(({ direction }) => direction === 'behind')
    const ahead = allSkew.filter(({ direction }) => direction === 'ahead')
    const alignSplit = splitProdDev(skewed.map(({ pkg }) => pkg))
    const alignCommands = combinedInstallCommands(
      pm,
      alignSplit.prod,
      alignSplit.dev,
    )
    if (skewed.length > 0) {
      p.log.warn(`Version skew detected:\n  ${skewLines(skewed)}`)
    }

    // What's missing outright (pinned, prod/dev split).
    const missing: string[] = []
    if (!stackPresent) missing.push(STACK_PACKAGE)
    if (integrationPkg && !integrationPresent) missing.push(integrationPkg)
    if (!cliPresent) missing.push(CLI_PACKAGE)
    const missingSplit = splitProdDev(missing)

    if (ahead.length > 0) {
      // Every release-train package versions in lockstep (the changesets
      // `fixed` group), so a train package strictly ahead of this CLI's embed
      // implies a stash release exists at that exact version — print the
      // command instead of leaving the user to research "the matching
      // release". Highest ahead version wins when several differ.
      const target = ahead
        .map(({ installed }) => installed)
        .reduce((max, v) => (compareVersions(v, max) > 0 ? v : max))
      const updateCmd = devInstallCommand(pm, `stash@${target}`)
      // Installing MISSING packages now would pin them to this CLI's older
      // embed, pairing them with the newer installed packages — a combination
      // no lockstep release ever shipped. Say so instead of silently
      // manufacturing the mismatch.
      const missingNote =
        missing.length > 0
          ? `\nNote: ${missing.join(', ')} will be installed at THIS release's versions, which may not match the newer packages above — for a consistent set, update stash first and re-run init:\n  ${updateCmd}`
          : `\nUpdate with:\n  ${updateCmd}\nthen re-run init.`
      p.log.warn(
        `Installed versions are newer than this release of stash:\n  ${aheadLines(ahead)}\nYour installs are likely fine — update the stash CLI to the matching release instead of downgrading.${missingNote}`,
      )
    }

    // Interactively, skewed packages can be aligned in the same install run.
    // Non-interactive runs never mutate an existing install: agents/CI get
    // the warning + exact commands above and keep going.
    const offerAlign = skewed.length > 0 && isInteractive()

    // Nothing missing and no interactive alignment to offer: `missing` empty
    // implies all three packages are present, so both flags are true.
    if (missing.length === 0 && !offerAlign) {
      if (skewed.length === 0) {
        const installed = integrationPkg
          ? `${STACK_PACKAGE}, ${integrationPkg} and ${CLI_PACKAGE}`
          : `${STACK_PACKAGE} and ${CLI_PACKAGE}`
        p.log.success(`${installed} are already installed.`)
      } else {
        // Non-interactive with skew: warned above; never mutate, print the fix.
        p.note(
          `Not changing installed packages (non-interactive). Align manually with:\n  ${alignCommands.join('\n  ')}`,
          'Version skew',
        )
      }
      return { ...state, stackInstalled: true, cliInstalled: true }
    }

    const prodPackages = [...missingSplit.prod]
    const devPackages = [...missingSplit.dev]

    const missingList = [
      ...missingSplit.prod.map((pkg) => `${pkg} (prod)`),
      ...missingSplit.dev.map((pkg) => `${pkg} (dev)`),
    ].join(', ')
    const promptParts: string[] = []
    if (missing.length > 0) promptParts.push(`Install ${missingList}`)
    if (offerAlign)
      promptParts.push(
        `align ${skewed.map(({ pkg }) => pkg).join(', ')} to this release`,
      )

    // Non-interactive (CI, agents, pipes): no TTY to answer, so install the
    // MISSING packages by default and continue rather than abort. `stash init`
    // is a setup command; installing its own dependencies is the expected
    // non-interactive default. (Alignment of existing installs is excluded
    // above — that mutation needs explicit consent.)
    if (!isInteractive()) {
      p.log.info(`Installing ${missingList} (non-interactive).`)
    } else if (offerAlign) {
      // The confirm below covers alignment too; include it in the commands.
      prodPackages.push(...alignSplit.prod)
      devPackages.push(...alignSplit.dev)
    }
    const commands = combinedInstallCommands(pm, prodPackages, devPackages)

    const install = isInteractive()
      ? await p.confirm({
          message: `${promptParts.join('; ')}? (${commands.join(' && ')})`,
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
        ...(stackInstalled ? [] : [`${pinnedSpec(STACK_PACKAGE)} (prod)`]),
        ...(integrationPkg && !integrationInstalled
          ? [`${pinnedSpec(integrationPkg)} (prod)`]
          : []),
        ...(cliInstalled ? [] : [`${pinnedSpec(CLI_PACKAGE)} (dev)`]),
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
