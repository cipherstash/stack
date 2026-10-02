import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import type { DetectedPackageManager, Integration } from './types.js'

interface PackageJson {
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
}

function readPackageJson(cwd: string): PackageJson | undefined {
  const pkgPath = resolve(cwd, 'package.json')
  if (!existsSync(pkgPath)) return undefined
  try {
    return JSON.parse(readFileSync(pkgPath, 'utf-8')) as PackageJson
  } catch {
    return undefined
  }
}

function hasDependency(pkg: PackageJson, name: string): boolean {
  return !!(pkg.dependencies?.[name] || pkg.devDependencies?.[name])
}

/**
 * Auto-detect the integration framework from the project's package.json.
 * Returns the first matching integration, or undefined.
 */
export function detectIntegration(cwd: string): Integration | undefined {
  const pkg = readPackageJson(cwd)
  if (!pkg) return undefined

  // Order matters — most specific first
  if (hasDependency(pkg, 'drizzle-orm')) return 'drizzle'
  if (hasDependency(pkg, '@supabase/supabase-js')) return 'supabase'
  if (hasDependency(pkg, 'prisma') || hasDependency(pkg, '@prisma/client'))
    return 'prisma'

  return undefined
}

/** Detect whether the project uses TypeScript. */
export function detectTypeScript(cwd: string): boolean {
  const pkg = readPackageJson(cwd)
  if (pkg && hasDependency(pkg, 'typescript')) return true
  return existsSync(resolve(cwd, 'tsconfig.json'))
}

export const PACKAGE_MANAGERS: Record<
  'bun' | 'pnpm' | 'yarn' | 'npm',
  DetectedPackageManager
> = {
  bun: {
    name: 'bun',
    installCommand: 'bun add',
    runCommand: 'bun run',
    execCommand: 'bunx',
  },
  pnpm: {
    name: 'pnpm',
    installCommand: 'pnpm add',
    runCommand: 'pnpm run',
    execCommand: 'pnpm dlx',
  },
  yarn: {
    name: 'yarn',
    installCommand: 'yarn add',
    runCommand: 'yarn run',
    execCommand: 'yarn dlx',
  },
  npm: {
    name: 'npm',
    installCommand: 'npm install',
    runCommand: 'npm run',
    execCommand: 'npx',
  },
}

/**
 * Identify a non-npm runner from `npm_config_user_agent`.
 *
 * `bunx`, `pnpm dlx`, and `yarn dlx` set this env var. We only trust non-npm
 * values: `npx` is frequently a reflex invocation and shouldn't override
 * lockfile detection, but `bunx` is a deliberate choice that should win.
 */
function packageManagerFromUserAgent(): DetectedPackageManager | undefined {
  const ua = process.env.npm_config_user_agent
  if (!ua) return undefined
  if (ua.startsWith('bun/')) return PACKAGE_MANAGERS.bun
  if (ua.startsWith('pnpm/')) return PACKAGE_MANAGERS.pnpm
  if (ua.startsWith('yarn/')) return PACKAGE_MANAGERS.yarn
  return undefined
}

/**
 * Detect the package manager used in the project.
 *
 * Priority: runtime user agent (bunx/pnpm dlx/yarn dlx) → lockfile → undefined.
 */
export function detectPackageManager(
  cwd: string,
): DetectedPackageManager | undefined {
  const fromUserAgent = packageManagerFromUserAgent()
  if (fromUserAgent) return fromUserAgent

  if (
    existsSync(resolve(cwd, 'bun.lockb')) ||
    existsSync(resolve(cwd, 'bun.lock'))
  ) {
    return PACKAGE_MANAGERS.bun
  }
  if (existsSync(resolve(cwd, 'pnpm-lock.yaml'))) return PACKAGE_MANAGERS.pnpm
  if (existsSync(resolve(cwd, 'yarn.lock'))) return PACKAGE_MANAGERS.yarn
  if (existsSync(resolve(cwd, 'package-lock.json'))) return PACKAGE_MANAGERS.npm
  return undefined
}
