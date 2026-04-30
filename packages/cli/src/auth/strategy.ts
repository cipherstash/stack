/**
 * Thin wrapper around `@cipherstash/auth` strategy detection.
 *
 * Centralises the NAPI-default-export shape and the swallow-on-failure
 * pattern used to decide whether the user is already authenticated. Other
 * commands that need an "are we logged in?" check can reuse
 * `resolveExistingAuth` instead of duplicating the try/catch + region-label
 * lookup. Tests can mock this single module rather than the NAPI library.
 */

import auth from '@cipherstash/auth'
import { regions } from '../commands/auth/login.js'

const { AutoStrategy } = auth

export interface ExistingAuth {
  workspace: string
  regionLabel: string
}

/** Construct a fresh `AutoStrategy` — exposed for tests that need to assert on detection. */
export function getAuthStrategy() {
  return AutoStrategy.detect()
}

/**
 * Resolve the currently-authenticated workspace if a valid token is
 * available, or `undefined` if not. Errors from `getToken()` (no creds,
 * expired tokens, network issues) are swallowed and treated as "not
 * authenticated" — the caller decides what to do next (typically: prompt
 * the user to log in).
 */
export async function resolveExistingAuth(): Promise<ExistingAuth | undefined> {
  try {
    const result = await getAuthStrategy().getToken()
    const regionEntry = regions.find((r) => result.issuer.includes(r.value))
    return {
      workspace: result.workspaceId,
      regionLabel: regionEntry?.label ?? 'unknown',
    }
  } catch {
    return undefined
  }
}
