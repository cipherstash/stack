import { existsSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import { detectPackageManager, runnerCommand } from '../init/utils.js'

export const CONFIG_FILENAME = 'stash.config.ts'

/** Default encryption-client path used when the project has none yet. */
export const DEFAULT_CLIENT_PATH = './src/encryption/index.ts'

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
 * Offer to create a `stash.config.ts` for the rest of the workflow.
 *
 * `eql install` itself doesn't need a config — it resolves the database URL
 * directly — but `db push` / `schema build` / `encrypt *` load the encryption
 * client through it, so we create it now as a convenience. Declining (or a
 * non-interactive context) never blocks the EQL install.
 *
 * Returns the encryption-client path the config points at, falling back to
 * {@link DEFAULT_CLIENT_PATH} when no config is written — so the caller can
 * still scaffold the client file at a sensible location.
 *
 * Should be called only when no config exists yet (the caller loads an existing
 * one instead); it never overwrites a present `stash.config.ts`.
 */
export async function offerStashConfig(
  cwd: string = process.cwd(),
): Promise<string> {
  const configPath = resolve(cwd, CONFIG_FILENAME)
  if (existsSync(configPath)) return DEFAULT_CLIENT_PATH

  const isTTY = Boolean(process.stdin.isTTY) && process.env.CI !== 'true'
  if (!isTTY) {
    // Non-interactive (CI / agents / pipes): create with a detected or default
    // client path rather than prompting, which would hang.
    const clientPath = detectClientPath(cwd) ?? DEFAULT_CLIENT_PATH
    writeFileSync(configPath, generateConfig(clientPath), 'utf-8')
    p.log.success(`Created ${CONFIG_FILENAME}`)
    return clientPath
  }

  const create = await p.confirm({
    message: `Create a ${CONFIG_FILENAME}? (needed later for db push / schema build / encrypt)`,
    initialValue: true,
  })
  if (p.isCancel(create) || !create) {
    p.log.info(
      `Skipped ${CONFIG_FILENAME}. Create it later with \`${runnerCommand(detectPackageManager(), 'stash init')}\`.`,
    )
    return DEFAULT_CLIENT_PATH
  }

  const clientPath = await resolveClientPath(cwd)
  if (!clientPath) return DEFAULT_CLIENT_PATH

  writeFileSync(configPath, generateConfig(clientPath), 'utf-8')
  p.log.success(`Created ${CONFIG_FILENAME}`)
  return clientPath
}
