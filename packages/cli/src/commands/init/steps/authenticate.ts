import * as p from '@clack/prompts'
import { resolveExistingAuth } from '../../../auth/strategy.js'
import { messages } from '../../../messages.js'
import { bindDevice, login, selectRegion } from '../../auth/login.js'
import type { InitProvider, InitState, InitStep } from '../types.js'

export const authenticateStep: InitStep = {
  id: 'authenticate',
  name: 'Authenticate with CipherStash',
  async run(state: InitState, provider: InitProvider): Promise<InitState> {
    const existing = await resolveExistingAuth()

    // Already authenticated — silently proceed. Users who want to switch
    // workspaces can run `stash auth login` directly. Asking on every
    // `init` is friction for the common "re-running init in the same repo"
    // flow.
    if (existing) {
      p.log.success(
        `${messages.auth.usingWorkspace}${existing.workspace} (${existing.regionLabel})`,
      )
      return { ...state, authenticated: true }
    }

    const region = await selectRegion()
    await login(region, provider.name)
    await bindDevice()
    return { ...state, authenticated: true }
  },
}
