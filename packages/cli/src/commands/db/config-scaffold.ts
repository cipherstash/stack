import { execSync } from 'node:child_process'
import { existsSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import {
  combinedInstallCommands,
  detectPackageManager,
  isPackageInstalled,
  runnerCommand,
} from '../init/utils.js'

export const CONFIG_FILENAME = 'stash.config.ts'

/**
 * The packages a scaffolded `stash.config.ts` depends on. `stash` (dev) exports
 * the `defineConfig`/`resolveDatabaseUrl` the config imports; `@cipherstash/stack`
 * (prod) is imported by the encryption client the config points at. Both must
 * resolve from the project's node_modules or `loadStashConfig` fails to load the
 * config with `Cannot find module 'stash'`.
 */
const CLI_PACKAGE = 'stash'
const STACK_PACKAGE = '@cipherstash/stack'

/**
 * Common locations where an encryption client file might live. Checked in
 * order of priority during auto-detection.
 */
const COMMON_CLIENT_PATHS = [
  './src/encryption/index.ts',
  './src/encryption.ts',
  './encryption/index.ts',
  './encryption.ts',
  './src/lib/encryption/index.ts',
  './src/lib/encryption.ts',
] as const

/**
 * Scan the project for an existing encryption client file at a common
 * location. Returns the first match, or `undefined`.
 */
export function detectClientPath(
  cwd: string = process.cwd(),
): string | undefined {
  for (const candidate of COMMON_CLIENT_PATHS) {
    if (existsSync(resolve(cwd, candidate))) return candidate
  }
  return undefined
}

/**
 * Prompt the user to confirm a detected client path, or enter one manually.
 * Returns the confirmed path, or `undefined` if the user cancels.
 */
export async function resolveClientPath(
  cwd: string = process.cwd(),
): Promise<string | undefined> {
  const detected = detectClientPath(cwd)

  if (detected) {
    const useDetected = await p.confirm({
      message: `Found encryption client at ${detected}. Use this path?`,
      initialValue: true,
    })

    if (p.isCancel(useDetected)) return undefined
    if (useDetected) return detected
  }

  const clientPath = await p.text({
    message: 'Where is your encryption client file?',
    placeholder: './src/encryption/index.ts',
    defaultValue: './src/encryption/index.ts',
    initialValue: detected ?? './src/encryption/index.ts',
    validate(value) {
      if (!value || value.trim().length === 0) {
        return 'Client file path is required.'
      }
      if (!value.endsWith('.ts')) {
        return 'Client file path must end with .ts'
      }
    },
  })

  if (p.isCancel(clientPath)) return undefined
  return clientPath
}

function generateConfig(clientPath: string): string {
  // The config calls resolveDatabaseUrl() at evaluation time. The CLI
  // walks a layered chain (--database-url flag → env → supabase status
  // → interactive prompt) and returns a usable URL. The connection
  // string is never persisted — only this declarative call is.
  return `import { defineConfig, resolveDatabaseUrl } from 'stash'

export default defineConfig({
  databaseUrl: await resolveDatabaseUrl(),
  client: '${clientPath}',
})
`
}

/**
 * Create a `stash.config.ts` at the project root if one doesn't already exist.
 * Returns `true` if a config is present (either pre-existing or freshly
 * written), `false` if the user cancelled the prompt.
 *
 * Invoked by `eql install` when no `stash.config.ts` exists, so users don't
 * need to run a separate `setup` step before installing EQL.
 */
export async function ensureStashConfig(
  cwd: string = process.cwd(),
): Promise<boolean> {
  const configPath = resolve(cwd, CONFIG_FILENAME)
  if (existsSync(configPath)) return true

  p.log.info(`No ${CONFIG_FILENAME} found — let's create one.`)

  const clientPath = await resolveClientPath(cwd)
  if (!clientPath) {
    p.cancel('Setup cancelled.')
    return false
  }

  writeFileSync(configPath, generateConfig(clientPath), 'utf-8')
  p.log.success(`Created ${CONFIG_FILENAME}`)
  return true
}

/**
 * Which config dependencies the project is missing, split by install kind.
 * Pure (only the filesystem probe in `isPackageInstalled`), so the decision is
 * unit-testable without spawning a package manager.
 */
export function missingConfigDependencies(cwd: string = process.cwd()): {
  prod: string[]
  dev: string[]
} {
  return {
    prod: isPackageInstalled(STACK_PACKAGE, cwd) ? [] : [STACK_PACKAGE],
    dev: isPackageInstalled(CLI_PACKAGE, cwd) ? [] : [CLI_PACKAGE],
  }
}

/**
 * Ensure the packages a `stash.config.ts` imports are installed before the CLI
 * tries to load it. Offers to install any missing ones interactively; in
 * non-interactive contexts (or on cancel / install failure) it prints the exact
 * install commands and returns `false` so the caller can stop cleanly.
 *
 * Without this, a standalone `npx stash eql install` scaffolds a config and then
 * crashes with a raw `Cannot find module 'stash'` because the CLI packages were
 * never added as project dependencies (only `stash init` does that) — #579.
 * Returns `true` when nothing is missing or the install succeeded.
 */
export async function ensureConfigDependencies(
  cwd: string = process.cwd(),
): Promise<boolean> {
  const { prod, dev } = missingConfigDependencies(cwd)
  if (prod.length === 0 && dev.length === 0) return true

  const pm = detectPackageManager()
  const commands = combinedInstallCommands(pm, prod, dev)
  const missing = [...prod, ...dev]
  const missingList = missing.join(', ')
  const verb = missing.length === 1 ? 'is' : 'are'

  const isTTY = Boolean(process.stdin.isTTY) && process.env.CI !== 'true'
  if (!isTTY) {
    p.log.warn(
      `${CONFIG_FILENAME} imports \`${CLI_PACKAGE}\`, but ${missingList} ${verb} not installed in this project.`,
    )
    p.note(
      `Install, then re-run:\n  ${commands.join('\n  ')}\n\nOr run \`${runnerCommand(pm, 'stash init')}\` to set everything up.`,
      'Missing dependencies',
    )
    return false
  }

  const proceed = await p.confirm({
    message: `Install ${missingList}? (${commands.join(' && ')})`,
  })
  if (p.isCancel(proceed) || !proceed) {
    p.note(
      `Install manually, then re-run:\n  ${commands.join('\n  ')}`,
      'Missing dependencies',
    )
    return false
  }

  for (const cmd of commands) {
    p.log.step(`Running: ${cmd}`)
    try {
      execSync(cmd, { cwd, stdio: 'inherit' })
    } catch {
      p.log.error(`Install failed: ${cmd}`)
      return false
    }
  }

  // Re-check from disk — a package manager can exit 0 without the package
  // actually resolving (registry hiccup, workspace mismatch).
  const still = missingConfigDependencies(cwd)
  if (still.prod.length > 0 || still.dev.length > 0) {
    p.log.warn(`Still missing: ${[...still.prod, ...still.dev].join(', ')}.`)
    return false
  }
  return true
}
