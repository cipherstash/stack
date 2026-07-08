import { existsSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'

export const CONFIG_FILENAME = 'stash.config.ts'

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
