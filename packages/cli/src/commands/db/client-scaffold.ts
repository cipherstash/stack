import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import * as p from '@clack/prompts'
import type { Integration } from '../init/types.js'
import { generatePlaceholderClient } from '../init/utils.js'
import { detectDrizzle, detectSupabase } from './detect.js'

/**
 * Pick a placeholder template using the same signals `eql install` already
 * detects. Drizzle wins over Supabase when both look present (a Drizzle-on-
 * Supabase project is more naturally scaffolded as Drizzle).
 */
function detectIntegration(
  cwd: string,
  databaseUrl: string | undefined,
): Integration {
  if (detectDrizzle(cwd)) return 'drizzle'
  if (detectSupabase(databaseUrl)) return 'supabase'
  return 'postgresql'
}

/**
 * Scaffold an encryption client file at `clientPath` if one doesn't exist.
 * No-op when the file is already present. Silent — never prompts.
 *
 * `init`'s `buildSchemaStep` is the primary path that creates this file
 * (and handles the "file already exists" case interactively). This function
 * exists as a safety net for users who run `eql install` directly without
 * `init` first — they still get a working client file rather than failing
 * later when the config tries to load a non-existent path.
 */
export function ensureEncryptionClient(
  clientPath: string,
  cwd: string = process.cwd(),
  databaseUrl: string | undefined = process.env.DATABASE_URL,
): void {
  const resolved = resolve(cwd, clientPath)
  if (existsSync(resolved)) return

  const integration = detectIntegration(cwd, databaseUrl)
  const contents = generatePlaceholderClient(integration)

  const dir = dirname(resolved)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  writeFileSync(resolved, contents, 'utf-8')

  p.log.success(
    `Scaffolded encryption client at ${clientPath} (${integration} template)`,
  )
}
