import { spawn } from 'node:child_process'
import * as p from '@clack/prompts'
import { pinnedSpec } from '../../runtime-versions.js'
import {
  detectPackageManager,
  isPackageInstalled,
  runnerCommand,
} from '../init/utils.js'

const WIZARD_PACKAGE = '@cipherstash/wizard'

/**
 * Resolve the runner invocation into argv-style tokens for `spawn`.
 *
 * `runnerCommand` returns strings like `'pnpm dlx @cipherstash/wizard'` or
 * `'npx @cipherstash/wizard'`. Splitting on whitespace is safe here because
 * every token is constructed from a closed enum (the package manager name
 * and the literal package). We avoid `shell: true` so we don't have to
 * worry about quoting user-passed flags downstream.
 */
function splitRunner(cmd: string): { bin: string; preArgs: string[] } {
  const tokens = cmd.split(/\s+/).filter(Boolean)
  const [bin, ...preArgs] = tokens
  if (!bin) {
    // Should be unreachable — runnerCommand always returns at least one token.
    throw new Error(`Empty runner command: "${cmd}"`)
  }
  return { bin, preArgs }
}

/**
 * Spawn `@cipherstash/wizard` and return its exit code.
 *
 * The wizard ships as its own package so the heavy agent SDK stays out of
 * the `stash` CLI bundle. Returning the exit code (rather than calling
 * `process.exit`) lets callers decide whether to abort: the top-level
 * `stash wizard` subcommand exits the process; the `init` handoff path
 * keeps init alive so it can run its outro, log final state, etc.
 */
export async function runWizardSpawn(
  passthroughArgs: string[],
): Promise<number> {
  const pm = detectPackageManager()
  // Pin the one-shot run to this release's wizard version (#661): a bare
  // `npx @cipherstash/wizard` resolves `latest`, which can lag or point at a
  // placeholder during pre-release windows — executing a DIFFERENT release
  // than the CLI that spawned it.
  const runner = runnerCommand(pm, pinnedSpec(WIZARD_PACKAGE))
  const cached = isPackageInstalled(WIZARD_PACKAGE)

  if (cached) {
    p.log.info('Launching the CipherStash wizard...')
  } else {
    p.log.info(
      `Launching the CipherStash wizard... first run downloads ${WIZARD_PACKAGE} (~5s).`,
    )
  }

  const { bin, preArgs } = splitRunner(runner)
  const args = [...preArgs, ...passthroughArgs]

  return new Promise<number>((resolvePromise) => {
    const child = spawn(bin, args, { stdio: 'inherit', shell: false })
    child.on('close', (code) => resolvePromise(code ?? 0))
    child.on('error', (err) => {
      p.log.error(`Failed to launch wizard: ${err.message}`)
      resolvePromise(127)
    })
  })
}

/**
 * Top-level `stash wizard` subcommand. Spawns the wizard and exits with
 * its exit code so users see the wizard's failure state directly. For the
 * in-process `init` handoff that wants to preserve init's lifecycle, call
 * `runWizardSpawn` instead.
 */
export async function wizardCommand(passthroughArgs: string[]): Promise<void> {
  const exitCode = await runWizardSpawn(passthroughArgs)
  if (exitCode !== 0) {
    process.exit(exitCode)
  }
}

export { splitRunner }
