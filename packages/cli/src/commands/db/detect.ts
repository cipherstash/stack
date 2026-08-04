import { existsSync, readFileSync, statSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'

/**
 * Return true when the connection string points at a Supabase-hosted Postgres.
 *
 * Supabase routes production connections through `*.supabase.co`,
 * `*.supabase.com`, and the pgBouncer pooler at `*.pooler.supabase.com`.
 * Matching on host means we auto-detect regardless of direct vs pooled
 * connection string.
 */
export function detectSupabase(databaseUrl: string | undefined): boolean {
  if (!databaseUrl) return false

  let host: string
  try {
    host = new URL(databaseUrl).hostname
  } catch {
    return false
  }

  return (
    host.endsWith('.supabase.co') ||
    host.endsWith('.supabase.com') ||
    host.endsWith('.pooler.supabase.com')
  )
}

/**
 * Information about the Supabase project layout in the current working
 * directory. Pure filesystem facts — no DB calls and no I/O beyond `existsSync`
 * / `statSync`.
 */
export interface SupabaseProjectInfo {
  /**
   * Whether the migrations directory exists AND is a directory. Together with
   * {@link hasConfigToml} this is what `stash init --supabase` reads to decide
   * whether the project has somewhere local to write an install migration —
   * a hosted Supabase project with no CLI scaffolding does not, and falls back
   * to a direct `eql install`.
   */
  hasMigrationsDir: boolean
  /**
   * Whether `supabase/config.toml` exists. The stronger of the two signals: a
   * project that has run `supabase init` but never written a migration has the
   * config and no migrations directory. Also gates the `supabase status`
   * fallback in the database-URL resolver.
   */
  hasConfigToml: boolean
  /**
   * Absolute path to the migrations directory to write into. Defaults to
   * `<cwd>/supabase/migrations`, or `override` (resolved against `cwd` when
   * relative) when supplied via `eql migration --supabase --out`.
   */
  migrationsDir: string
}

/**
 * Inspect the working directory for Supabase CLI scaffolding.
 *
 * IMPORTANT: this is a hint — it does NOT enable `--supabase`. The user must
 * pass `--supabase` explicitly for the migration-file flow to activate
 * (`stash init --supabase` counts as that explicit choice).
 *
 * `migrationsDir` is returned whether or not it exists, because it is also the
 * path `eql migration --supabase` creates.
 *
 * @param cwd - Project root to inspect.
 * @param override - Optional `--out` override. Absolute paths are used as-is;
 *   relative paths are resolved against `cwd`.
 */
export function detectSupabaseProject(
  cwd: string,
  override?: string,
): SupabaseProjectInfo {
  const migrationsDir = override
    ? isAbsolute(override)
      ? override
      : resolve(cwd, override)
    : resolve(cwd, 'supabase', 'migrations')

  const hasMigrationsDir = existsAsDirectory(migrationsDir)
  const hasConfigToml = existsSync(resolve(cwd, 'supabase', 'config.toml'))

  return { hasMigrationsDir, hasConfigToml, migrationsDir }
}

function existsAsDirectory(path: string): boolean {
  if (!existsSync(path)) return false
  try {
    return statSync(path).isDirectory()
  } catch {
    return false
  }
}

/**
 * Return true when the project uses Drizzle.
 *
 * We look for a `drizzle.config.*` file at the cwd (fast path) or
 * `drizzle-orm` / `drizzle-kit` listed in the project's package.json.
 * Either signal alone is enough — Drizzle users always have at least one.
 */
export function detectDrizzle(cwd: string): boolean {
  const configCandidates = [
    'drizzle.config.ts',
    'drizzle.config.js',
    'drizzle.config.mjs',
    'drizzle.config.cjs',
  ]
  for (const candidate of configCandidates) {
    if (existsSync(resolve(cwd, candidate))) return true
  }

  const pkgPath = resolve(cwd, 'package.json')
  if (!existsSync(pkgPath)) return false

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as {
      dependencies?: Record<string, unknown>
      devDependencies?: Record<string, unknown>
      peerDependencies?: Record<string, unknown>
      optionalDependencies?: Record<string, unknown>
    }
    const deps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies,
    }
    return 'drizzle-orm' in deps || 'drizzle-kit' in deps
  } catch {
    return false
  }
}

/**
 * Return true when the project uses Prisma Next.
 *
 * Detected via a `prisma-next.config.*` at the cwd (fast path) or
 * a `@prisma-next/cli` / `@cipherstash/stack-prisma` entry in
 * package.json. Either signal alone is enough.
 */
export function detectPrismaNext(cwd: string): boolean {
  const configCandidates = [
    'prisma-next.config.ts',
    'prisma-next.config.js',
    'prisma-next.config.mjs',
    'prisma-next.config.cjs',
  ]
  for (const candidate of configCandidates) {
    if (existsSync(resolve(cwd, candidate))) return true
  }

  const pkgPath = resolve(cwd, 'package.json')
  if (!existsSync(pkgPath)) return false

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as {
      dependencies?: Record<string, unknown>
      devDependencies?: Record<string, unknown>
      peerDependencies?: Record<string, unknown>
      optionalDependencies?: Record<string, unknown>
    }
    const deps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.peerDependencies,
      ...pkg.optionalDependencies,
    }
    return '@prisma-next/cli' in deps || '@cipherstash/stack-prisma' in deps
  } catch {
    return false
  }
}
