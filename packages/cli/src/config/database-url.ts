/**
 * Layered DATABASE_URL resolution. Called from inside the user's
 * `stash.config.ts` via:
 *
 *   import { defineConfig, resolveDatabaseUrl } from 'stash'
 *   export default defineConfig({
 *     databaseUrl: await resolveDatabaseUrl(),
 *   })
 *
 * The CLI's `loadStashConfig` wraps the jiti-import in
 * `withResolverContext({ databaseUrlFlag, supabase })` (an
 * `AsyncLocalStorage` scope) before evaluating the config file. Any
 * `resolveDatabaseUrl()` call inside the file then sees those options
 * via `als.getStore()` and walks:
 *
 *   1. `--database-url <url>` flag (explicit override).
 *   2. `process.env.DATABASE_URL` (shell, mise, direnv, dotenv files
 *      loaded by `bin/stash.ts`).
 *   3. `supabase status --output env` → `DB_URL`, when `--supabase` is
 *      set OR a `supabase/config.toml` is detected.
 *   4. Interactive `p.text` prompt (skipped under `CI=true` or non-TTY
 *      stdin).
 *   5. Hard-fail with a source-naming error.
 *
 * Returns the resolved URL string. The CLI never mutates
 * `process.env.DATABASE_URL` — the URL is only carried in the value
 * `defineConfig` returns. The connection string is never persisted to
 * disk; `stash.config.ts` references this function, not a literal.
 *
 * Concurrency: the ALS context is per-async-flow, so multiple
 * concurrent `loadStashConfig` calls (e.g. parallel test cases or a
 * programmatic batch invocation) each get isolated options without
 * stepping on each other.
 */

import { AsyncLocalStorage } from 'node:async_hooks'
import { execSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import * as p from '@clack/prompts'
import { detectSupabaseProject } from '../commands/db/detect.js'
import { detectPackageManager, runnerCommand } from '../commands/init/utils.js'
import { messages } from '../messages.js'
import { isCiEnv } from './tty.js'

export interface ResolveDatabaseUrlOptions {
  /** Value of `--database-url` if the user passed one. */
  databaseUrlFlag?: string
  /** Value of `--supabase` flag. Triggers the supabase-status fallback. */
  supabase?: boolean
  /** Override cwd for project detection (mainly for tests). */
  cwd?: string
}

// The CLI ships as two tsup bundles (`dist/index.js` for the library and
// `dist/bin/stash.js` for the binary), each of which contains its own copy
// of this file. A bare `new AsyncLocalStorage()` would therefore produce
// two independent stores: the CLI sets context on the binary's instance,
// the user's config (loaded via jiti from inside the binary process)
// imports from the library bundle and reads from a different instance, so
// nothing propagates. Rendezvous via a `Symbol.for`-keyed slot on
// `globalThis` so both bundles share a single ALS for the lifetime of the
// process. Behaviour is identical to a plain module-level `als` — the
// concurrency guarantees come from `AsyncLocalStorage`, not from where
// the instance is parked.
const ALS_KEY = Symbol.for('cipherstash.cli.database-url-als')
type AlsHolder = {
  [ALS_KEY]?: AsyncLocalStorage<ResolveDatabaseUrlOptions>
}
const alsHolder = globalThis as AlsHolder
if (!alsHolder[ALS_KEY]) {
  alsHolder[ALS_KEY] = new AsyncLocalStorage<ResolveDatabaseUrlOptions>()
}
const als = alsHolder[ALS_KEY]

/**
 * Run `fn` inside an ALS scope that exposes `opts` to any
 * `resolveDatabaseUrl()` call descendant from this async-flow.
 *
 * Used by `loadStashConfig` to thread CLI flag values into the user's
 * config evaluation without mutating `process.env` or any other shared
 * state.
 */
export function withResolverContext<T>(
  opts: ResolveDatabaseUrlOptions,
  fn: () => Promise<T>,
): Promise<T> {
  return als.run(opts, fn)
}

/** Walk dotenv precedence and pick the first existing file. Defaults to `.env`. */
export function detectDotenvFile(cwd: string = process.cwd()): string {
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
  const runner = runnerCommand(detectPackageManager(), '').trim()
  // `runner` is one of 'npx' | 'bunx' | 'pnpm dlx' | 'yarn dlx'.
  // Split on whitespace because pnpm/yarn dlx uses two tokens.
  const dlxArgs = runner.split(/\s+/)
  const candidates: Array<readonly [string, readonly string[]]> = [
    ['supabase', ['status', '--output', 'env']],
    [
      dlxArgs[0],
      [...dlxArgs.slice(1), 'supabase', 'status', '--output', 'env'],
    ],
  ]

  for (const [cmd, args] of candidates) {
    try {
      const out = execSync(`${cmd} ${args.join(' ')}`, {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore'],
        timeout: 5_000,
      })
      const match = out.match(/^(?:DB_URL|db_url)=(?:"([^"]+)"|(\S+))/m)
      const value = match?.[1] ?? match?.[2]
      if (value && isUrlParseable(value)) return value
    } catch {
      // binary missing, project not started, parse error — fall through.
    }
  }
  return undefined
}

async function promptForUrl(cwd: string): Promise<string | undefined> {
  // Surface the alternative paths before prompting so users don't feel
  // like they're stuck in an interactive flow when a flag or env var
  // would do. The dotenv file in the tip is detected from cwd so it
  // matches what the user actually has (`.env.local` vs `.env` etc.).
  p.note(messages.db.urlPromptTip(detectDotenvFile(cwd)))

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
 * Walk the resolution chain and return a usable DATABASE_URL. Reads
 * options from the surrounding `withResolverContext` scope (set by the
 * CLI before evaluating the config file); any explicit `opts` passed
 * here override the scoped values.
 *
 * Exits 1 when no source resolves a URL.
 */
export async function resolveDatabaseUrl(
  opts: ResolveDatabaseUrlOptions = {},
): Promise<string> {
  const ctx: ResolveDatabaseUrlOptions = { ...als.getStore(), ...opts }
  const cwd = ctx.cwd ?? process.cwd()

  // 1. Flag.
  if (ctx.databaseUrlFlag !== undefined) {
    const trimmed = ctx.databaseUrlFlag.trim()
    if (!trimmed || !isUrlParseable(trimmed)) {
      p.log.error(messages.db.urlFlagMalformed)
      process.exit(1)
    }
    p.log.info(messages.db.urlResolvedFromFlag)
    return trimmed
  }

  // 2. Existing env (shell, mise, direnv, dotenv files).
  const fromEnv = process.env.DATABASE_URL?.trim()
  if (fromEnv && fromEnv.length > 0) {
    return fromEnv
  }

  // 3. Supabase fallback — opted-in, or the project clearly is one.
  const supabaseProject = detectSupabaseProject(cwd)
  if (ctx.supabase || supabaseProject.hasConfigToml) {
    const fromSupabase = trySupabaseStatus()
    if (fromSupabase) {
      p.log.info(messages.db.urlResolvedFromSupabase)
      return fromSupabase
    }
  }

  // 4. Interactive prompt — skipped in CI / non-TTY. `isCiEnv` accepts the
  // common CI-truthy spellings (`true`, `1`, case-insensitive) since not every
  // CI provider sets `CI=true` exactly; shared with the region resolver.
  const isCi = isCiEnv()
  const isInteractive = Boolean(process.stdin.isTTY) && !isCi
  if (isInteractive) {
    const fromPrompt = await promptForUrl(cwd)
    if (fromPrompt) {
      p.log.info(messages.db.urlResolvedFromPrompt)
      // Hint the user toward making it stick so they don't get re-prompted.
      p.note(messages.db.urlHint(detectDotenvFile(cwd)))
      return fromPrompt
    }
  }

  // 5. Hard fail.
  p.log.error(
    isCi ? messages.db.urlMissingCi : messages.db.urlMissingInteractive,
  )
  process.exit(1)
}
