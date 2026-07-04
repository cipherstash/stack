import type { InitProvider, InitState } from '../types.js'
import { type PackageManager, runnerCommand } from '../utils.js'

export function createBaseProvider(): InitProvider {
  return {
    name: 'base',
    introMessage: 'Setting up CipherStash for your project...',
    getNextSteps(state: InitState, pm: PackageManager): string[] {
      const cli = runnerCommand(pm, 'stash')
      const manualEdit = state.clientFilePath
        ? `edit ${state.clientFilePath} directly`
        : 'edit your encryption schema directly'
      return [
        `Set up your database: ${cli} eql install`,
        `Customize your schema: ${cli} wizard (AI-guided, automated) — or ${manualEdit}`,
        'Quickstart: https://cipherstash.com/docs/stack/quickstart',
        'Dashboard: https://dashboard.cipherstash.com/workspaces',
      ]
    },
  }
}
