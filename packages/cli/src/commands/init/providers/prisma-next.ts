import type { InitProvider } from '../types.js'
import { type PackageManager, runnerCommand } from '../utils.js'

export function createPrismaNextProvider(): InitProvider {
  return {
    name: 'prisma-next',
    introMessage: 'Setting up CipherStash for your Prisma Next project...',
    // Note: Prisma Next absorbs the EQL bundle install and schema
    // scaffold steps via its migration framework. The next-steps list
    // below therefore points at `prisma-next migration plan|apply`
    // instead of `stash eql install`, and at `cipherstashFromStack`
    // instead of an `encryption/index.ts` placeholder.
    getNextSteps(_state, pm: PackageManager): string[] {
      const stash = runnerCommand(pm, 'stash')
      const prismaNext = runnerCommand(pm, 'prisma-next')
      return [
        'Declare encrypted columns in prisma/schema.prisma using cipherstash.Encrypted*()',
        'Register the extension: add `cipherstash` to `extensionPacks` in prisma-next.config.ts',
        `Generate the contract: ${prismaNext} contract emit`,
        `Plan + apply (installs the EQL bundle alongside your app schema): ${prismaNext} migration plan && ${prismaNext} migration apply`,
        'Wire the runtime: cipherstashFromStack({ contractJson }) — see @cipherstash/prisma-next/stack',
        `Customize your schema: ${stash} wizard (AI-guided, automated)`,
        'Prisma Next guide: https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next',
        'Dashboard: https://dashboard.cipherstash.com/workspaces',
        'Need help? Discord or support@cipherstash.com',
      ]
    },
  }
}
