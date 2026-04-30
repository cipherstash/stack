/**
 * Layered DATABASE_URL resolution for DB-touching CLI commands.
 *
 * The scaffolded `stash.config.ts` always references `process.env.DATABASE_URL`
 * (see `commands/db/config-scaffold.ts`). When users haven't already exported
 * the var (or written it to one of the dotenv files we auto-load in
 * `bin/stash.ts`), we walk a chain of fallback sources and populate
 * `process.env.DATABASE_URL` in-process so the existing `loadStashConfig`
 * path Just Works. The connection string is never written to disk by this
 * resolver — `stash.config.ts` keeps its declarative env reference.
 *
 * Source order (first hit wins; later sources fall through silently if a
 * prior source errors transiently):
 *   1. `--database-url <url>` flag (explicit override).
 *   2. `process.env.DATABASE_URL` (shell, mise, direnv, dotenv files).
 *   3. `supabase status --output env` → `DB_URL`, when `--supabase` is set
 *      OR a `supabase/config.toml` is detected.
 *   4. Interactive `p.text` prompt (skipped under `CI=true` or non-TTY stdin).
 *
 * If all sources fail, exits 1 with a message naming each source tried.
 */

import { execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import * as p from '@clack/prompts'
import { detectSupabaseProject } from '../commands/db/detect.js'
import { messages } from '../messages.js'

export type DatabaseUrlSource = 'flag' | 'env' | 'supabase-status' | 'prompt'

export interface ResolveDatabaseUrlOptions {
  /** Value of `--database-url` if the user passed one. */
  databaseUrlFlag?: string
  /** Value of `--supabase` flag. Triggers the supabase-status fallback. */
  supabase?: boolean
  /** Override cwd for project detection (mainly for tests). */
  cwd?: string
}

export interface ResolveDatabaseUrlResult {
  url: string
  source: DatabaseUrlSource
}

/** Walk dotenv precedence and pick the first existing file. Defaults to `.env`. */
function detectDotenvFile(cwd: string): string {
  const candidates = [
    '.env.local',
    '.env.development.local',
    '.env.development',
    '.env',
  ]
  for (const file of candidates) {
    if (existsSync(join(cwd, file))) return file
  }
  return '.env'
}

function isUrlParseable(value: string): boolean {
  try {
    new URL(value)
    return true
  } catch {
    return false
  }
}

/** Try to extract a `DB_URL=...` value from `supabase status --output env`. */
function trySupabaseStatus(): string | undefined {
  // Two invocation forms in case the user has supabase locally vs. only via npx.
  const candidates = [
    ['supabase', ['status', '--output', 'env']],
    ['npx', ['--no-install', 'supabase', 'status', '--output', 'env']],
  ] as const

  for (const [cmd, args] of candidates) {
    try {
      const out = execSync(`${cmd} ${args.join(' ')}`, {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5_000,
      })
      // `supabase status --output env` emits shell-style KEY=value lines.
      // The variable name has historically been `DB_URL` but defensive parse
      // is cheap.
      const match = out.match(/^(?:DB_URL|db_url)=(?:"([^"]+)"|(\S+))/m)
      const value = match?.[1] ?? match?.[2]
      if (value && isUrlParseable(value)) return value
    } catch {
      // binary missing, project not started, parse error — fall through.
    }
  }
  return undefined
}

async function promptForUrl(): Promise<string | undefined> {
  const value = await p.text({
    message: messages.db.urlPromptMessage,
    validate: (v) => {
      if (!v || v.trim().length === 0) return messages.db.urlInvalid
      if (!isUrlParseable(v.trim())) return messages.db.urlInvalid
      return undefined
    },
  })
  if (p.isCancel(value)) {
    p.cancel(messages.auth.cancelled)
    process.exit(0)
  }
  return value.trim()
}

/**
 * Resolve a usable DATABASE_URL through the layered chain. On success,
 * mutates `process.env.DATABASE_URL` (only when previously unset/empty, or
 * when the source was an explicit `--database-url` flag) so downstream
 * config loading sees a populated env. Returns the resolved URL plus its
 * source for logging.
 *
 * Exits 1 when no source resolves a URL.
 */
export async function resolveDatabaseUrl(
  options: ResolveDatabaseUrlOptions = {},
): Promise<ResolveDatabaseUrlResult> {
  const cwd = options.cwd ?? process.cwd()

  // 1. Flag.
  if (options.databaseUrlFlag !== undefined) {
    const trimmed = options.databaseUrlFlag.trim()
    if (!trimmed || !isUrlParseable(trimmed)) {
      p.log.error(messages.db.urlFlagMalformed)
      process.exit(1)
    }
    // Explicit override always wins — overwrite env so the rest of this
    // process sees the user's intended URL.
    process.env.DATABASE_URL = trimmed
    p.log.info(messages.db.urlResolvedFromFlag)
    return { url: trimmed, source: 'flag' }
  }

  // 2. Existing env (covers shell, mise, direnv, dotenv loads in bin/stash.ts).
  const fromEnv = process.env.DATABASE_URL?.trim()
  if (fromEnv && fromEnv.length > 0) {
    return { url: fromEnv, source: 'env' }
  }

  // 3. Supabase fallback — only if the user opted in or the project clearly is one.
  const supabaseProject = detectSupabaseProject(cwd)
  if (options.supabase || supabaseProject.hasConfigToml) {
    const fromSupabase = trySupabaseStatus()
    if (fromSupabase) {
      // Mutate env only when previously unset (this branch implies it was).
      process.env.DATABASE_URL = fromSupabase
      p.log.info(messages.db.urlResolvedFromSupabase)
      return { url: fromSupabase, source: 'supabase-status' }
    }
  }

  // 4. Interactive prompt — skipped in CI / non-TTY.
  const isCi = process.env.CI === 'true'
  const isInteractive = Boolean(process.stdin.isTTY) && !isCi
  if (isInteractive) {
    const fromPrompt = await promptForUrl()
    if (fromPrompt) {
      process.env.DATABASE_URL = fromPrompt
      p.log.info(messages.db.urlResolvedFromPrompt)
      // Nudge the user toward making this stick. detectDotenvFile picks the
      // first file already present, defaulting to `.env`.
      p.note(messages.db.urlHint(detectDotenvFile(cwd)))
      return { url: fromPrompt, source: 'prompt' }
    }
  }

  // 5. Hard fail.
  p.log.error(
    isCi ? messages.db.urlMissingCi : messages.db.urlMissingInteractive,
  )
  process.exit(1)
}
