import { describe, expect, it } from 'vitest'
import { type SetupPromptContext, renderSetupPrompt } from '../setup-prompt.js'

const baseCtx: SetupPromptContext = {
  integration: 'drizzle',
  encryptionClientPath: './src/encryption/index.ts',
  packageManager: 'pnpm',
  schemaFromIntrospection: false,
  eqlInstalled: true,
  stackInstalled: true,
  cliInstalled: true,
  handoff: 'claude-code',
  mode: 'implement',
  installedSkills: ['stash-encryption', 'stash-drizzle', 'stash-cli'],
  usesProxy: false,
}

describe('renderSetupPrompt — orient + route (implement mode)', () => {
  it('emits integration + package manager in the header', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('Integration: `drizzle`')
    expect(out).toContain('Package manager: `pnpm`')
  })

  it('explicitly tells the agent its first response is a routing question, not an action', () => {
    const out = renderSetupPrompt(baseCtx)
    // The agent must orient + ask before editing anything. The earlier
    // version of this prompt drove the agent into a fixed TODO list which
    // pushed it past the user's actual intent.
    expect(out).toContain('Your first response')
    expect(out).toMatch(/Before any edits/)
    expect(out).toMatch(/orientation message/)
  })

  it('describes both supported flows and explicitly forbids in-place conversion', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('### Add a new encrypted column')
    expect(out).toContain('### Migrate an existing column to encrypted')
    expect(out).toContain('### Converting in place is not supported')
  })

  it('frames the migrate-existing flow as encryption rollout + cutover with a deploy gate', () => {
    // The whole point of the rewrite. No "phase" jargon; explicit deploy
    // gate banner; rollout vs cutover named sections.
    const out = renderSetupPrompt(baseCtx)
    expect(out).toMatch(/encryption rollout/i)
    expect(out).toMatch(/encryption cutover/i)
    expect(out).toMatch(/deploy gate/i)
    expect(out).not.toMatch(/phase 1|phase 2|four-deploy/i)
  })

  it('mentions the staged twin model in the migrate-existing flow', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toMatch(/<col>_encrypted/)
    expect(out).toMatch(/dual-?writ/i)
  })

  it('sharpens the dual-write definition to "every persistence path, same transaction, every code branch"', () => {
    // Agents previously interpreted "writes both columns" loosely and missed
    // branches. The prompt has to be explicit so a single missed code path
    // does not silently produce drift after backfill.
    const out = renderSetupPrompt(baseCtx)
    expect(out).toMatch(/every persistence path/i)
    expect(out).toMatch(/same transaction/i)
    expect(out).toMatch(/every code branch/i)
  })

  it('points the agent at `stash status` as the canonical "where am I" command', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('## Where am I?')
    expect(out).toMatch(/pnpm dlx stash status/)
  })

  it('tells the agent that impl will refuse cutover-step plans without a recorded dual_writing event', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toMatch(/refuse to run cutover-step plans/i)
    expect(out).toMatch(/dual_writing/)
  })

  it('names the lifecycle CLI commands inline in the migrate-existing flow', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('pnpm dlx stash encrypt backfill')
    expect(out).toContain('pnpm dlx stash encrypt cutover')
    expect(out).toContain('pnpm dlx stash encrypt drop')
    expect(out).toContain('--confirm-dual-writes-deployed')
    expect(out).toContain('--force')
  })

  it('emits drizzle-kit commands in the add-new-column flow for drizzle integration', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('pnpm exec drizzle-kit generate')
    expect(out).toContain('pnpm exec drizzle-kit migrate')
  })

  it('emits supabase migration commands for supabase integration', () => {
    const out = renderSetupPrompt({
      ...baseCtx,
      integration: 'supabase',
      installedSkills: ['stash-encryption', 'stash-supabase', 'stash-cli'],
    })
    expect(out).toContain('supabase migration new')
  })

  it('uses the right runner per package manager in the add-new-column flow', () => {
    const npm = renderSetupPrompt({ ...baseCtx, packageManager: 'npm' })
    const bun = renderSetupPrompt({ ...baseCtx, packageManager: 'bun' })
    const yarn = renderSetupPrompt({ ...baseCtx, packageManager: 'yarn' })

    expect(npm).toContain('npx --no-install drizzle-kit generate')
    expect(bun).toContain('bun x drizzle-kit generate')
    expect(yarn).toContain('yarn drizzle-kit generate')
  })

  it('uses the right CLI runner for stash encrypt commands per package manager', () => {
    const npm = renderSetupPrompt({ ...baseCtx, packageManager: 'npm' })
    const bun = renderSetupPrompt({ ...baseCtx, packageManager: 'bun' })

    expect(npm).toContain('npx stash encrypt backfill')
    expect(bun).toContain('bunx stash encrypt backfill')
  })

  it('introduces every installed skill with a one-line purpose', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('`stash-encryption`')
    expect(out).toContain('`stash-drizzle`')
    expect(out).toContain('`stash-cli`')
    // Each skill line should explain what the skill is for, not just name it.
    expect(out).toMatch(/`stash-encryption`.*lifecycle/i)
    expect(out).toMatch(/`stash-drizzle`.*Drizzle/i)
    expect(out).toMatch(/`stash-cli`.*command reference/i)
  })

  it('points each handoff at the right rule location', () => {
    const claude = renderSetupPrompt({ ...baseCtx, handoff: 'claude-code' })
    const codex = renderSetupPrompt({ ...baseCtx, handoff: 'codex' })
    const agents = renderSetupPrompt({ ...baseCtx, handoff: 'agents-md' })

    expect(claude).toContain('.claude/skills/')
    expect(codex).toContain('.codex/skills/')
    expect(codex).toContain('AGENTS.md')
    expect(agents).toContain('AGENTS.md')
    expect(agents).not.toContain('.claude/skills/')
    expect(agents).not.toContain('.codex/skills/')
  })

  it('handles the empty-skills fallback gracefully', () => {
    // Defensive case — when bundled skills are missing, installSkills
    // returns []. The rendered prompt must still make sense, just without
    // skill enumeration.
    const out = renderSetupPrompt({
      ...baseCtx,
      handoff: 'claude-code',
      installedSkills: [],
    })
    expect(out).not.toMatch(/the {2,}skill/)
    // Still describes both flows so the agent can route.
    expect(out).toContain('### Add a new encrypted column')
    expect(out).toContain('### Migrate an existing column to encrypted')
  })

  it('preserves stop-and-ask invariants', () => {
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('## Stop and ask the user when')
    expect(out).toMatch(/convert a populated column in place/i)
  })

  it('flags the bundler exclusion for projects using @cipherstash/stack', () => {
    // Skipping serverExternalPackages / webpack externals is the most
    // common Next.js footgun — the agent missed it on the spike project.
    // The prompt should call this out explicitly in the add-new-column
    // walkthrough so it's visible without having to read the skill.
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('serverExternalPackages')
    expect(out).toContain('@cipherstash/protect-ffi')
  })

  it('directs the agent to read .cipherstash/plan.md first if it exists', () => {
    // Plan mode produces .cipherstash/plan.md; if the user later runs init
    // again in implement mode, the plan must be the source of truth — not
    // a re-asked routing question.
    const out = renderSetupPrompt(baseCtx)
    expect(out).toContain('.cipherstash/plan.md')
    expect(out).toMatch(/source of truth/i)
  })
})

describe('renderSetupPrompt — plan mode (rollout, default)', () => {
  const planCtx: SetupPromptContext = {
    ...baseCtx,
    mode: 'plan',
    planStep: 'rollout',
  }

  it('frames the deliverable as a rollout plan file, not code changes', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain(
      '# CipherStash setup — write an encryption rollout plan',
    )
    expect(out).toContain('.cipherstash/plan.md')
    expect(out).toMatch(/produce.*rollout plan file/i)
  })

  it('explicitly forbids mutating commands during planning', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('## What you must NOT do')
    expect(out).toMatch(/db push/)
    expect(out).toMatch(/encrypt backfill/)
    expect(out).toMatch(/encrypt cutover/)
    expect(out).toMatch(/encrypt drop/)
  })

  it('allows read-only inspection commands and points at `stash status`', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/db status/)
    expect(out).toContain('## Where am I?')
    expect(out).toMatch(/pnpm dlx stash status/)
    expect(out).toMatch(/Read-only/i)
  })

  it('tells the agent to offer copying the rollout plan into docs/plans when it exists', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('docs/plans/')
    expect(out).toMatch(/offer to copy/i)
  })

  it('lists project-specific risk classes the plan must cover', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/bundler exclusion/i)
    expect(out).toMatch(/top-level-await/i)
    expect(out).toMatch(/partial CipherStash/i)
  })

  it('explicitly excludes cutover-step work from the rollout plan', () => {
    // The whole reason for the split. The rollout plan stops at the deploy
    // gate; cutover work is a separate plan written later.
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/encryption-cutover plan.*separate plan/i)
    expect(out).toMatch(/Stay in scope/i)
  })

  it('still tells the agent its first response is an orientation message, not action', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('## Your first response')
    expect(out).toMatch(/orientation message/i)
  })

  it('references concrete table/column names from .cipherstash/context.json', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('.cipherstash/context.json')
  })

  it('instructs the agent to begin the plan with a machine-readable summary block, with step="rollout"', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('cipherstash:plan-summary')
    expect(out).toContain('"step": "rollout"')
    expect(out).toContain('"columns"')
    expect(out).toContain('"new"')
    expect(out).toContain('"migrate"')
    expect(out).toMatch(/at the very top of the file/i)
  })

  it('preserves the integration + package manager header in plan mode', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('Integration: `drizzle`')
    expect(out).toContain('Package manager: `pnpm`')
  })

  it('does not emit the implement-mode flow walkthroughs verbatim', () => {
    // Plan mode summarises the work in one or two lines per option rather
    // than restating the full numbered walkthroughs; the walkthroughs live
    // in the implement prompt.
    const out = renderSetupPrompt(planCtx)
    expect(out).not.toContain('### Add a new encrypted column')
    expect(out).not.toContain('### Migrate an existing column to encrypted')
  })
})

describe('renderSetupPrompt — plan mode (cutover)', () => {
  const planCtx: SetupPromptContext = {
    ...baseCtx,
    mode: 'plan',
    planStep: 'cutover',
  }

  it('frames the deliverable as a cutover plan file', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain(
      '# CipherStash setup — write an encryption cutover plan',
    )
    expect(out).toMatch(/produce the cutover plan file/i)
  })

  it('declares dual-writes already deployed and the rollout out of scope', () => {
    // The cutover plan must not re-walk the user through schema-add or
    // dual-write code; that's done. Backfill onwards is the scope.
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/dual-writes are recorded as live/i)
    expect(out).toMatch(/already deployed to production/i)
    expect(out).toMatch(/off-scope/i)
  })

  it('summary block uses step="cutover" with path="migrate" guidance', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('"step": "cutover"')
    expect(out).toMatch(/path.*"migrate".*for every column/i)
  })

  it('covers backfill, schema rename + db push, cutover, read path, drop', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/backfill/i)
    expect(out).toMatch(/cutover/i)
    expect(out).toMatch(/drop/i)
    expect(out).toMatch(/read[ -]path/i)
    expect(out).toMatch(/Remove dual-writes/i)
  })

  it('still instructs read-only operation only', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('## What you must NOT do')
  })

  it('does not regress into rollout-step framing', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).not.toContain(
      '# CipherStash setup — write an encryption rollout plan',
    )
  })
})

describe('renderSetupPrompt — plan mode (complete escape hatch)', () => {
  const planCtx: SetupPromptContext = {
    ...baseCtx,
    mode: 'plan',
    planStep: 'complete',
  }

  it('frames the deliverable as a complete-rollout plan file', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain(
      '# CipherStash setup — write a complete encryption rollout plan',
    )
  })

  it('warns prominently that the deploy gate is skipped', () => {
    // The escape hatch is dangerous against a deployed app. The prompt
    // must make sure the agent surfaces this loudly to the user before
    // writing the plan, not in a footnote.
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/escape hatch/i)
    expect(out).toMatch(/skips the production-deploy gate/i)
    expect(out).toMatch(/not.*serving a deployed application/i)
  })

  it('summary block uses step="complete"', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toContain('"step": "complete"')
  })

  it('covers the full lifecycle without a deploy gate between rollout and cutover', () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/full lifecycle/i)
    expect(out).toMatch(/no deploy gate between rollout and cutover/i)
  })

  it("first response asks the user to confirm there is no deployed application", () => {
    const out = renderSetupPrompt(planCtx)
    expect(out).toMatch(/this database isn't backing a deployed application/i)
  })
})

describe('renderSetupPrompt — plan mode default when planStep is unset', () => {
  it('falls back to the rollout template (the most common starting point)', () => {
    // Callers that don't yet plumb planStep through (legacy tests, the
    // wizard's handoff-helpers, etc.) get the rollout-shaped plan. That
    // matches a fresh project: no events recorded, the user is starting
    // out, the rollout is the next sane step.
    const ctx: SetupPromptContext = { ...baseCtx, mode: 'plan' }
    const out = renderSetupPrompt(ctx)
    expect(out).toContain(
      '# CipherStash setup — write an encryption rollout plan',
    )
  })
})

describe('renderSetupPrompt — usesProxy conditional', () => {
  describe('implement mode with usesProxy: false (SDK-only)', () => {
    it('drops db push step from add-new-column flow', () => {
      const out = renderSetupPrompt({ ...baseCtx, usesProxy: false })
      expect(out).not.toMatch(/5\.\s*Register the encryption config/)
      // Step 5 should now be the wire-the-column step, not db push
      expect(out).toMatch(/5\.\s*Wire the column through/)
    })

    it('drops register-pending-config step from rollout path', () => {
      const out = renderSetupPrompt({ ...baseCtx, usesProxy: false })
      // Should have only "Schema-add" as step 1, then "Dual-write" as step 2
      // (no "Register pending config" in between)
      expect(out).toMatch(/1\.\s*\*\*Schema-add/)
      expect(out).toMatch(/2\.\s*\*\*Dual-write/)
      // Register pending config should not appear in the rollout section
      const rolloutSection = out.substring(
        out.indexOf('#### Encryption rollout'),
        out.indexOf('⛔'),
      )
      expect(rolloutSection).not.toMatch(/Register pending config/)
    })

    it('keeps encrypt cutover invocation and notes the pending-config workaround', () => {
      const out = renderSetupPrompt({ ...baseCtx, usesProxy: false })
      const cutoverSection = out.substring(
        out.indexOf('#### Encryption cutover'),
      )
      // Should mention encrypt cutover
      expect(cutoverSection).toMatch(/encrypt cutover/)
      // SDK-only setups still hit the pending-config gap, so the cutover
      // step must call out the `db push` workaround for that error.
      expect(cutoverSection).toMatch(/No pending EQL configuration/)
      expect(cutoverSection).toMatch(/db push/)
    })
  })

  describe('implement mode with usesProxy: true (Proxy)', () => {
    it('includes db push step in add-new-column flow', () => {
      const out = renderSetupPrompt({ ...baseCtx, usesProxy: true })
      expect(out).toMatch(/5\.\s*Register the encryption config.*db push/)
      expect(out).toMatch(/6\.\s*\*\*If db push wrote pending\*\*.*db activate/)
    })

    it('includes register-pending-config step in rollout path', () => {
      const out = renderSetupPrompt({ ...baseCtx, usesProxy: true })
      expect(out).toMatch(/2\.\s*\*\*Register pending config.*db push/)
      expect(out).toMatch(/3\.\s*\*\*Dual-write/)
    })

    it('includes full db push in cutover step', () => {
      const out = renderSetupPrompt({ ...baseCtx, usesProxy: true })
      const cutoverSection = out.substring(
        out.indexOf('#### Encryption cutover'),
      )
      expect(cutoverSection).toMatch(/5\.\s*\*\*Switch the schema and re-push/)
      expect(cutoverSection).toMatch(/Run.*db push.*again/)
    })
  })

  describe('plan mode (rollout) with usesProxy conditional', () => {
    it('mentions db push in rollout plan summary when usesProxy: true', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'rollout',
        usesProxy: true,
      })
      expect(out).toMatch(
        /Encryption rollout.*dual-write code, and.*db push.*writes pending/,
      )
    })

    it('notes db push as Proxy-only in rollout plan summary when usesProxy: false', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'rollout',
        usesProxy: false,
      })
      expect(out).toMatch(
        /Encryption rollout.*dual-write code.*plus.*db push.*Proxy users only/,
      )
    })

    it('includes db push in rollout PR contents when usesProxy: true', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'rollout',
        usesProxy: true,
      })
      expect(out).toMatch(/schema-add.*db push.*pending.*dual-write code/)
    })

    it('drops db push from rollout PR contents when usesProxy: false', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'rollout',
        usesProxy: false,
      })
      expect(out).toMatch(/schema-add.*dual-write code/)
      // Should not mention "db push (pending)" in the rollout PR contents
      const prSection = out.substring(
        out.indexOf('migrate columns: what the rollout PR contains'),
      )
      expect(prSection).not.toMatch(/db push.*pending/)
    })
  })

  describe('plan mode (cutover) with usesProxy conditional', () => {
    it('includes db push in schema-rename when usesProxy: true', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'cutover',
        usesProxy: true,
      })
      expect(out).toMatch(/Schema rename and re-push/)
      expect(out).toMatch(/db push.*registers the renamed/)
    })

    it('separates schema rename from db push when usesProxy: false', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'cutover',
        usesProxy: false,
      })
      expect(out).toMatch(/\*\*Schema rename\.\*\*.*original column/)
      expect(out).toMatch(/Proxy users only.*db push/)
    })

    it('notes db push as Proxy-only in prose when usesProxy: false', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'cutover',
        usesProxy: false,
      })
      expect(out).toMatch(/schema-edit step.*exact rename pattern/)
      expect(out).not.toMatch(/schema-edit.*db push.*step/i)
    })
  })

  describe('plan mode (complete) with usesProxy conditional', () => {
    it('includes db push steps in full lifecycle when usesProxy: true', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'complete',
        usesProxy: true,
      })
      expect(out).toMatch(/db push.*backfill.*schema rename.*db push.*cutover/)
    })

    it('drops both db push mentions from full lifecycle when usesProxy: false', () => {
      const out = renderSetupPrompt({
        ...baseCtx,
        mode: 'plan',
        planStep: 'complete',
        usesProxy: false,
      })
      expect(out).toMatch(/schema-add.*dual-write code.*backfill.*schema rename/)
      // The lifecycle line should not have "db push" twice
      const migrateSection = out.substring(
        out.indexOf('**Migrate existing columns**'),
      )
      const firstLine = migrateSection.split('\n')[0]
      const dbPushCount = (firstLine.match(/db push/g) || []).length
      expect(dbPushCount).toBe(0)
    })
  })
})
