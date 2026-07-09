import { existsSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import { DEFAULT_CLIENT_PATH } from '../../config/index.js'
import { isInteractive } from '../../config/tty.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'

export const CONFIG_FILENAME = 'stash.config.ts'

// Re-exported so scaffold consumers (and their tests) have a single import site.
export { DEFAULT_CLIENT_PATH }

/**
 * Common locations where an encryption client file might live. Checked in
 * order of priority during auto-detection — the default path leads.
 */
const COMMON_CLIENT_PATHS = [
  DEFAULT_CLIENT_PATH,
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
    placeholder: DEFAULT_CLIENT_PATH,
    defaultValue: DEFAULT_CLIENT_PATH,
    initialValue: detected ?? DEFAULT_CLIENT_PATH,
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

/** Write the config with the given client path and report it. */
function writeStashConfig(configPath: string, clientPath: string): string {
  writeFileSync(configPath, generateConfig(clientPath), 'utf-8')
  p.log.success(`Created ${CONFIG_FILENAME}`)
  return clientPath
}

/**
 * Create a `stash.config.ts` for the rest of the workflow (`db push` /
 * `schema build` / `encrypt *` load the encryption client through it).
 * `eql install` itself doesn't need one — it resolves the database URL
 * directly — so this is a setup convenience, never a blocker.
 *
 * - `opts.ensure` (used by `stash init`, where the user has already committed
 *   to setup) creates the config without a yes/no prompt.
 * - Otherwise it *offers* to create it interactively. A non-interactive run
 *   (CI / agents / pipes) can't prompt, so it does nothing rather than silently
 *   writing files that reference packages a bare project may not have installed.
 *
 * Returns the encryption-client path the config points at when a config was
 * written, or `null` when nothing was created (declined, non-interactive, or an
 * existing config) — so the caller skips the client scaffold too.
 *
 * Should be called only when no config exists yet (the caller loads an existing
 * one instead); it never overwrites a present `stash.config.ts`.
 */
export async function offerStashConfig(
  opts: { ensure?: boolean; cwd?: string } = {},
): Promise<string | null> {
  const cwd = opts.cwd ?? process.cwd()
  const configPath = resolve(cwd, CONFIG_FILENAME)
  if (existsSync(configPath)) return null

  // `ensure` (init) creates the config without asking — the user already
  // committed to setup by running `stash init`.
  if (opts.ensure) {
    return writeStashConfig(
      configPath,
      detectClientPath(cwd) ?? DEFAULT_CLIENT_PATH,
    )
  }

  // 'offer' mode. A non-interactive run can't prompt; don't write into the
  // project unasked (that could drop files importing uninstalled packages) —
  // the missing-config guidance points the user at `stash init` later.
  if (!isInteractive()) return null

  const create = await p.confirm({
    message: `Create a ${CONFIG_FILENAME}? (needed later for db push / schema build / encrypt)`,
    initialValue: true,
  })
  if (p.isCancel(create) || !create) {
    p.log.info(
      `Skipped ${CONFIG_FILENAME}. Create it later with \`${runnerCommand(detectPackageManager(), 'stash init')}\`.`,
    )
    return null
  }

  const clientPath = await resolveClientPath(cwd)
  if (!clientPath) return null

  return writeStashConfig(configPath, clientPath)
}
