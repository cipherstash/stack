import auth from '@cipherstash/auth'
import * as p from '@clack/prompts'
import { bindDevice, login, regions, resolveRegion } from '../../auth/login.js'
import type { InitProvider, InitState, InitStep } from '../types.js'

const { AutoStrategy } = auth

interface ExistingAuth {
  workspace: string
  regionLabel: string
}

/**
 * Check if the user is already authenticated with a valid token.
 * Uses OAuthStrategy.getToken() which handles refresh automatically.
 */
async function checkExistingAuth(): Promise<ExistingAuth | undefined> {
  try {
    const strategy = AutoStrategy.detect()
    const result = await strategy.getToken()

    const regionEntry = regions.find((r) => result.issuer.includes(r.value))
    const regionLabel = regionEntry?.label ?? 'unknown'

    return { workspace: result.workspaceId, regionLabel }
  } catch {
    return undefined
  }
}

export const authenticateStep: InitStep = {
  id: 'authenticate',
  name: 'Authenticate with CipherStash',
  async run(state: InitState, provider: InitProvider): Promise<InitState> {
    const existing = await checkExistingAuth()

    // Already authenticated — silently proceed. Users who want to switch
    // workspaces can run `stash auth login` directly. Asking on every
    // `init` is friction for the common "re-running init in the same repo"
    // flow.
    if (existing) {
      p.log.success(
        `Using workspace ${existing.workspace} (${existing.regionLabel})`,
      )
      return { ...state, authenticated: true }
    }

    // Honour `--region` / `STASH_REGION` so `stash init` can run
    // non-interactively; falls back to the interactive picker in a TTY, or a
    // clean error (no hang) in an agent / CI context without a region set.
    const region = await resolveRegion({ regionFlag: state.regionFlag })
    await login(region, provider.name)
    await bindDevice()
    return { ...state, authenticated: true }
  },
}
