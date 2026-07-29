/**
 * The CLI and the wizard each own a `SKILL_MAP`, and the two must agree: both
 * install skills into the same `.claude/skills` / `.codex/skills` directory of
 * the same user project, so a user who ran `npx stash init` and a user who ran
 * the wizard would otherwise end up with different guidance for the same
 * integration. The maps drift silently — nothing imports one from the other.
 *
 * This assertion lives HERE, not in either package's own suite, because it is
 * the only workspace that declares both `stash` and `@cipherstash/wizard` as
 * dependencies. It reads source rather than a built binary (the same idiom as
 * `package-managers.e2e.test.ts` Suite A) so it needs no build step, and
 * `pnpm --filter @cipherstash/e2e run typecheck` compiles `tests/**` — which
 * makes a relocated module a compile error in CI rather than a module-not-found
 * inside an unrelated package's unit run.
 *
 * The integration names differ by design: the CLI names the packages
 * (`prisma-next`, `postgresql`), the wizard names the user's situation
 * (`prisma`, `generic`). The mapping below is the whole contract.
 */

import { describe, expect, it } from 'vitest'

import { SKILL_MAP as CLI_SKILL_MAP } from '../../packages/cli/src/commands/init/lib/install-skills.js'
import type { Integration as CliIntegration } from '../../packages/cli/src/commands/init/types.js'
import { SKILL_MAP as WIZARD_SKILL_MAP } from '../../packages/wizard/src/lib/install-skills.js'
import type { Integration as WizardIntegration } from '../../packages/wizard/src/lib/types.js'

// Exhaustive over the wizard union: a new wizard integration added without a
// CLI counterpart fails to compile here, rather than shipping a divergent set.
const EQUIVALENT: Record<WizardIntegration, CliIntegration> = {
  drizzle: 'drizzle',
  supabase: 'supabase',
  prisma: 'prisma-next',
  generic: 'postgresql',
}

describe('CLI and wizard SKILL_MAP parity', () => {
  it('installs the same skills for every equivalent integration', () => {
    for (const [wizardName, cliName] of Object.entries(EQUIVALENT) as Array<
      [WizardIntegration, CliIntegration]
    >) {
      expect(
        WIZARD_SKILL_MAP[wizardName],
        `${wizardName} (wizard) vs ${cliName} (cli)`,
      ).toEqual(CLI_SKILL_MAP[cliName])
    }
  })

  // Both unions are closed, so parity over `EQUIVALENT` is only complete while
  // it covers every CLI integration too — a CLI-only integration would slip
  // through the loop above unnoticed.
  it('covers every integration on both sides', () => {
    expect(Object.keys(WIZARD_SKILL_MAP).sort()).toEqual(
      Object.keys(EQUIVALENT).sort(),
    )
    expect(Object.keys(CLI_SKILL_MAP).sort()).toEqual(
      Object.values(EQUIVALENT).sort(),
    )
  })
})
