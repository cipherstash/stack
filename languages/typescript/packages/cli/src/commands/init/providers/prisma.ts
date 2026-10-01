import type { InitProvider } from '../types.js'
import { type PackageManager, runnerCommand } from '../utils.js'

/**
 * The `--prisma` provider. It backs the Prisma Next framework (the only
 * Prisma integration Stack ships), so `provider.name` is the short,
 * `--supabase`/`--drizzle`-consistent `'prisma'` used for referrer tracking,
 * while the internal `Integration` value it resolves to stays `'prisma-next'`
 * (see build-schema.ts) — that keeps skill/dependency/prompt wiring on the
 * existing Prisma Next path.
 */
export function createPrismaProvider(): InitProvider {
  return {
    name: 'prisma',
    selected: ['prisma'],
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
        'Declare encrypted columns in prisma/schema.prisma using cipherstash.TextSearch(), cipherstash.DateOrd(), …',
        'Register the extension: add `cipherstash` to `extensionPacks` in prisma-next.config.ts',
        `Generate the contract: ${prismaNext} contract emit`,
        `Plan + apply (installs the EQL bundle alongside your app schema): ${prismaNext} migration plan && ${prismaNext} migrate`,
        'Wire the runtime: cipherstashFromStack({ contractJson }) — see @cipherstash/stack-prisma/stack',
        `Customize your schema: ${stash} wizard (AI-guided, automated)`,
        'Prisma Next guide: https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next',
        'Dashboard: https://dashboard.cipherstash.com/workspaces',
        'Need help? Discord or support@cipherstash.com',
      ]
    },
  }
}
