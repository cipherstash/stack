import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import auth from '@cipherstash/auth'
import { detectPackageManager } from './detect.js'

interface PrerequisiteResult {
  ok: boolean
  missing: string[]
}

/**
 * Check that all wizard prerequisites are met:
 * 1. CipherStash authentication exists
 * 2. stash.config.ts exists in the project
 */
export async function checkPrerequisites(
  cwd: string,
): Promise<PrerequisiteResult> {
  const missing: string[] = []
  const runner = detectPackageManager(cwd)?.execCommand ?? 'npx'

  if (!(await hasCredentials())) {
    missing.push(
      `Not authenticated with CipherStash. Run: ${runner} stash auth login`,
    )
  }

  if (!findStashConfig(cwd)) {
    missing.push(`No stash.config.ts found. Run: ${runner} stash db install`)
  }

  return { ok: missing.length === 0, missing }
}

// Ask @cipherstash/auth to resolve credentials via its own profile logic
// rather than probing a hardcoded path — the on-disk layout has shifted
// between auth versions and duplicating it in the CLI is what caused
// CIP-2996 in the first place.
async function hasCredentials(): Promise<boolean> {
  try {
    await auth.AutoStrategy.detect().getToken()
    return true
  } catch (error) {
    const code = (error as { code?: string } | null)?.code
    if (code === 'NOT_AUTHENTICATED' || code === 'MISSING_WORKSPACE_CRN') {
      return false
    }
    throw error
  }
}

/** Walk up from cwd to find stash.config.ts. */
function findStashConfig(startDir: string): string | undefined {
  let dir = resolve(startDir)
  while (true) {
    const candidate = resolve(dir, 'stash.config.ts')
    if (existsSync(candidate)) return candidate

    const jsCandidate = resolve(dir, 'stash.config.js')
    if (existsSync(jsCandidate)) return jsCandidate

    const parent = resolve(dir, '..')
    if (parent === dir) return undefined
    dir = parent
  }
}
