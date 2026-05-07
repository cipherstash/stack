import type { PlanStep } from './parse-plan.js'
import type { HandoffChoice, InitMode, Integration } from '../types.js'
import { type PackageManager, runnerCommand } from '../utils.js'

export const PLAN_REL_PATH = '.cipherstash/plan.md'

export interface SetupPromptContext {
  integration: Integration
  encryptionClientPath: string
  packageManager: PackageManager
  schemaFromIntrospection: boolean
  eqlInstalled: boolean
  stackInstalled: boolean
  cliInstalled: boolean
  /** Which handoff option the user picked. Lets us tailor wording (e.g. the
   *  Codex prompt names AGENTS.md, Claude names the skill). */
  handoff: HandoffChoice
  /** Whether the agent should produce a plan first or implement directly.
   *  Drives the entire prompt body — plan-mode tells the agent its task is
   *  to produce `.cipherstash/plan.md`; implement-mode is the orient-and-
   *  route action prompt. */
  mode: InitMode
  /** Names of skills `stash init` copied into the project (e.g.
   *  `stash-encryption`, `stash-drizzle`, `stash-cli`). The action prompt
   *  names them so the agent knows which references to consult. Empty for
   *  the `agents-md` handoff (no skills directory installed) and for
   *  `wizard` (the wizard installs its own). */
  installedSkills: string[]
  /** In plan mode, which scope of plan to produce. The `stash plan` command
   *  picks this by reading `cs_migrations` (`rollupPlanStep`); the user
   *  override is `--complete-rollout`. Ignored in implement mode. Defaults
   *  to `'rollout'` when plan mode is invoked without explicit state — that
   *  matches a fresh project where there are no recorded events yet. */
  planStep?: PlanStep
}

interface MigrationCommands {
  generate: string
  apply: string
  /** Human-readable label for the migration tool ("Drizzle Kit", "Prisma"). */
  tool: string
}

/**
 * Per-integration migration commands. Used in the "add a new encrypted
 * column" walkthrough so the prompt names the exact strings the agent
 * should run, not a generic "run your migrations" hand-wave.
 */
function migrationCommands(
  integration: Integration,
  pm: PackageManager,
): MigrationCommands | undefined {
  if (integration === 'drizzle') {
    return {
      tool: 'Drizzle Kit',
      generate: `${execCommand(pm)} drizzle-kit generate`,
      apply: `${execCommand(pm)} drizzle-kit migrate`,
    }
  }
  if (integration === 'supabase') {
    return {
      tool: 'Supabase CLI',
      generate: 'supabase migration new <name>',
      apply: 'supabase migration up (remote) or supabase db reset (local)',
    }
  }
  return undefined
}

/**
 * Map the package manager to the right "run a binary from node_modules" form.
 *   npm  → `npx --no-install` (avoid surprise downloads when the dep should
 *           already be installed)
 *   pnpm → `pnpm exec`
 *   yarn → `yarn` (yarn 1) or `yarn run` — `yarn <bin>` works for both
 *   bun  → `bun x` (binary-runner mode, not the dlx alias)
 */
function execCommand(pm: PackageManager): string {
  switch (pm) {
    case 'npm':
      return 'npx --no-install'
    case 'pnpm':
      return 'pnpm exec'
    case 'yarn':
      return 'yarn'
    case 'bun':
      return 'bun x'
  }
}

function bullet(line: string): string {
  return `- ${line}`
}

function checked(line: string): string {
  return `- [x] ${line}`
}

/**
 * Phrase the "where the rules live" pointer for each handoff target.
 *
 *   claude-code → skills loaded into `.claude/skills/`
 *   codex       → AGENTS.md (durable doctrine) + skills in `.codex/skills/`
 *   agents-md   → AGENTS.md only (Cursor / Windsurf / Cline don't load
 *                 skill directories, so the rules are inlined there)
 *   wizard      → handled separately; this prompt isn't written for wizard
 */
function rulesLocation(handoff: HandoffChoice): string {
  if (handoff === 'claude-code') return '`.claude/skills/`'
  if (handoff === 'codex')
    return '`.codex/skills/` plus durable rules in `AGENTS.md`'
  return '`AGENTS.md` (Cursor / Windsurf / Cline)'
}

/**
 * One-line purpose for each skill so the prompt can introduce them by what
 * they're for, not just by name. Returned in the order the user is most
 * likely to consult them.
 */
const SKILL_PURPOSES: Record<string, string> = {
  'stash-encryption':
    'the encryption API, schema definition, and the rollout-and-cutover lifecycle (the source of truth for taking encryption to production)',
  'stash-drizzle':
    'Drizzle-specific patterns: declaring encrypted columns, query operators, the rollout/cutover walkthrough for an existing column',
  'stash-supabase':
    'Supabase-specific patterns: `encryptedSupabase` wrapper, encrypted query filters, transparent decryption, the rollout/cutover walkthrough',
  'stash-dynamodb':
    'DynamoDB encryption: per-item encrypt/decrypt, HMAC attribute keys, audit logging',
  'stash-cli':
    '`stash` command reference — `status`, `plan`, `impl`, `db install`, `encrypt {backfill,cutover,drop}`, etc.',
  'stash-secrets':
    'storing and retrieving encrypted secrets (separate concern from column encryption)',
  'stash-supply-chain-security':
    'supply-chain controls (post-install policy, lockfile integrity, etc.)',
}

function renderSkillIndex(installedSkills: string[]): string {
  if (installedSkills.length === 0) {
    return 'No skills were installed (handoff likely wrote AGENTS.md only — read that for the rules).'
  }
  return installedSkills
    .map((name) => {
      const purpose = SKILL_PURPOSES[name] ?? '(no description)'
      return `- **\`${name}\`** — ${purpose}`
    })
    .join('\n')
}

/**
 * Render the project-specific action prompt. Dispatches to the plan-mode or
 * implement-mode renderer based on `ctx.mode`. Both produce the same shape
 * (orient → describe options → tell the agent what its first response is)
 * but the *deliverable* differs: plan-mode writes `.cipherstash/plan.md`,
 * implement-mode edits code and runs lifecycle commands.
 */
export function renderSetupPrompt(ctx: SetupPromptContext): string {
  return ctx.mode === 'plan'
    ? renderPlanPrompt(ctx)
    : renderImplementPrompt(ctx)
}

function setupChecklist(ctx: SetupPromptContext): string[] {
  const done: string[] = [
    checked('Authenticated to CipherStash and selected a workspace'),
    checked(`Detected integration: \`${ctx.integration}\``),
    checked(
      `Wrote a placeholder encryption client at \`${ctx.encryptionClientPath}\` (a small file showing the encryption-client patterns; the user's real Drizzle/Supabase schema files remain authoritative)`,
    ),
  ]
  if (ctx.stackInstalled) {
    done.push(checked('Installed `@cipherstash/stack` (runtime)'))
  }
  if (ctx.cliInstalled) {
    done.push(checked('Installed `stash` (CLI, dev dep)'))
  }
  if (ctx.eqlInstalled) {
    done.push(
      checked(
        'Installed the EQL extension and `cipherstash.cs_migrations` into the database',
      ),
    )
  }
  return done
}

/**
 * Render the implementation action prompt.
 *
 * This is the file the agent reads first after `stash init` hands off in
 * implement mode. It does NOT prescribe a fixed sequence of edits — the
 * agent doesn't yet know what the user wants. Instead the prompt:
 *
 *   1. Confirms what setup is complete.
 *   2. Names the skills loaded and what each is for.
 *   3. Explains the two real options for encrypting a column (add a new
 *      encrypted column from scratch, or migrate an existing populated
 *      column via the encryption rollout + cutover lifecycle). In-place
 *      conversion is not supported and called out as such.
 *   4. Tells the agent its FIRST response should be a routing question, not
 *      an action.
 *   5. Lists the "stop and ask" rules that override flow mechanics.
 *
 * If `.cipherstash/plan.md` exists (a previous `stash plan` run), the
 * prompt directs the agent to read it first and treat it as the source
 * of truth for routing — the user has already done the orientation pass.
 */
export function renderImplementPrompt(ctx: SetupPromptContext): string {
  const cli = runnerCommand(ctx.packageManager, 'stash')
  const migration = migrationCommands(ctx.integration, ctx.packageManager)

  const sections: string[] = [
    '# CipherStash setup — orient and ask',
    '',
    `Integration: \`${ctx.integration}\` · Package manager: \`${ctx.packageManager}\``,
    '',
    '`stash init` has finished its mechanical setup. Your job is **not** to start editing schema or running migrations immediately. Your job is to **orient the user with the two real options for encrypting a column, then ask which one they want before touching anything**. Pick concrete table/column names from `.cipherstash/context.json` when describing the options so the user can recognise their own data.',
    '',
    '## Where am I?',
    '',
    `Run \`${cli} status\` before you start editing. It is disk-only, idempotent, and tells you which encryption rollouts are in flight, which have been deployed, and what's left. Re-run it after every transition — never act blind.`,
    '',
    '## Existing plan',
    '',
    `Before anything else, check whether \`${PLAN_REL_PATH}\` exists. If it does, the user has already done a planning pass with you (or another agent). Read it as the source of truth for which path applies, which tables/columns are in scope, and the deploy ordering — do not re-ask the routing question. Confirm with the user that the plan is still current, then execute it. If the plan looks stale (the schema or context has moved on), say so and propose specific updates rather than starting fresh.`,
    '',
    `If \`${PLAN_REL_PATH}\` does **not** exist, proceed with the orient-and-route flow below.`,
    '',
    '## What `stash init` already did',
    '',
    ...setupChecklist(ctx),
    '',
    '## Skills loaded',
    '',
    `Reusable rules and worked examples live in ${rulesLocation(ctx.handoff)}:`,
    '',
    renderSkillIndex(ctx.installedSkills),
    '',
    'Read the skills before answering API or pattern questions. The doctrine in `AGENTS.md` (or its inlined equivalent) covers the invariants that apply regardless of which flow you take — never log plaintext, never `.notNull()` on creation, etc.',
    '',
    '## The two options',
    '',
    "There are exactly two supported ways to encrypt a column. Recognise which one applies to the user's request before doing anything.",
    '',
    '### Add a new encrypted column',
    '',
    'Use when the column **does not yet exist** in the database (no plaintext predecessor to preserve). This is normal Drizzle / Supabase work plus the encryption client patterns from the integration skill.',
    '',
    "1. **If this is the first encrypted column in the project, configure the bundler exclusion first.** `@cipherstash/stack` cannot be bundled (it wraps a native FFI module). Next.js: add `serverExternalPackages: ['@cipherstash/stack', '@cipherstash/protect-ffi']` to `next.config.*`. Webpack: `externals`. esbuild: `external`. Vite SSR: `ssr.external`. Without this, the encryption client crashes at runtime with `Cannot find module '@cipherstash/protect-ffi-*'`. See the `stash-encryption` skill's Installation section for the full snippets.",
    "2. Edit the user's real schema file (`src/db/schema.ts` or wherever they keep it) to declare the new encrypted column. Use the patterns in the integration skill — `encryptedType` for Drizzle, `encryptedColumn` for Supabase. Encrypted columns must be **nullable `jsonb`** at creation time. Never `.notNull()`.",
    `3. Generate the schema migration${migration ? ` — \`${migration.generate}\` (${migration.tool})` : " using the project's existing migration tooling"}.`,
    `4. Show the user the generated SQL before applying${migration ? ` — \`${migration.apply}\`` : ''}.`,
    `5. Register the encryption config — \`${cli} db push\`. If the project has no active EQL config yet (first encrypted column ever), this writes directly to active and you can skip step 6. If an active config already exists, push writes \`pending\` and prints a next-step note.`,
    `6. **If db push wrote pending**, promote it to active — \`${cli} db activate\`. (Use \`${cli} db activate\` here because no rename is needed; \`${cli} encrypt cutover\` is reserved for the migrate-existing-column flow.)`,
    '7. Wire the column through the application code: insert paths encrypt before write, select paths decrypt after read, query paths use the right operator (`protectOps.eq`, etc. — see the integration skill).',
    '8. Verify with a round-trip: insert a record, select it back, confirm the value decrypts and the search ops work.',
    '',
    '### Migrate an existing column to encrypted',
    '',
    "Use when the column **already exists** in the user's database and contains live data that must be preserved.",
    '',
    "Why it's staged: there is no atomic way to replace a populated column with an encrypted one without corrupting data. Instead, taking encryption to production happens in two passes around a deploy gate. The first pass — the **encryption rollout** — adds the encrypted twin column and the dual-write code; the user deploys that to production so every new write produces both plaintext and ciphertext. The second pass — the **encryption cutover** — backfills historical rows, renames the encrypted twin into the original column name, switches reads through the encryption client, and drops the old plaintext column.",
    '',
    '#### Encryption rollout — what lands before the deploy',
    '',
    `1. **Schema-add.** Add a \`<col>_encrypted\` twin column (nullable \`jsonb\`) alongside the existing plaintext column in the user's real schema file. Generate and apply the schema migration. **If this is the first encrypted column in the project, configure the bundler exclusion now** — see the snippets in the previous section. Without it, importing the encryption client at backfill time will crash.`,
    `2. **Register pending config** — \`${cli} db push\`. With an existing active config, this writes the new column-set as \`pending\`. Cutover (later) will promote it. (If this is the very first push for the project, db push writes active directly — fine, the rest of the flow still works.)`,
    `3. **Dual-write.** Edit the application code so **every persistence path that mutates this row writes both \`<col>\` (plaintext, unchanged) and \`<col>_encrypted\` (ciphertext via the encryption client) — in the same transaction, on every code branch, with no exceptions.** A single missed branch causes silent migration drift later. Reads still come from the plaintext column.`,
    '',
    `⛔ **Deploy gate.** Stop here. The application must be running this code in production — the deployed environment that owns the database — before backfill is safe to run. "Live on the user's laptop" or "live in CI" does not count. After the user deploys, tell them to run`,
    '',
    `   \`${cli} status\``,
    '',
    `to confirm where they are, then \`${cli} plan\` to draft the cutover. Do not run \`${cli} encrypt backfill\`, \`${cli} encrypt cutover\`, or \`${cli} encrypt drop\` until that has happened — \`${cli} impl\` will refuse to run cutover-step plans without a recorded \`dual_writing\` event.`,
    '',
    '#### Encryption cutover — after dual-writes are live',
    '',
    `4. **Backfill.** Run \`${cli} encrypt backfill --table <T> --column <c>\`. The CLI prompts the user (or accepts \`--confirm-dual-writes-deployed\` non-interactively) to confirm dual-writes are live, then chunks through the existing rows. Resumable; checkpoints to \`cs_migrations\` after every chunk. SIGINT-safe.`,
    `5. **Switch the schema and re-push, then cutover.** Update the schema file to declare the encrypted column under its final name (drop \`_encrypted\` suffix, switch \`<col>\` to \`encryptedType\`). Run \`${cli} db push\` again — pending now reflects the renamed shape. Then \`${cli} encrypt cutover --table <T> --column <c>\` runs the rename in one transaction (\`<col>\` → \`<col>_plaintext\`, \`<col>_encrypted\` → \`<col>\`) and promotes pending → active.`,
    '6. **Wire the read path through the encryption client.** Post-cutover, `<col>` holds ciphertext. Read code paths must decrypt before returning the value to callers — `decryptModel(row, table)` for Drizzle, the `encryptedSupabase` wrapper for Supabase, or the equivalent `decrypt`/`bulkDecryptModels` calls. Without this step, your read paths return raw `eql_v2_encrypted` payloads to end users. The integration skill has the exact API.',
    '7. **Remove the dual-write code.** The plaintext column is now `<col>_plaintext` and is no longer authoritative. Delete the dual-write logic from the persistence layer.',
    `8. **Drop.** Run \`${cli} encrypt drop --table <T> --column <c>\`. Generates a migration that removes the now-unused \`<col>_plaintext\`. Apply with the project's normal migration tooling.`,
    '',
    'Recovery: if the user reports that backfill ran *before* the dual-write code was actually live, drift is expected (rows written during the backfill window land in plaintext only). Re-run with `--force` to encrypt every plaintext row regardless of current state.',
    '',
    '### Converting in place is not supported',
    '',
    'There is no supported way to drop a populated plaintext column and replace it with an encrypted column atomically — any "just swap the type" approach corrupts data or loses constraints. If the user asks for that, explain why it doesn\'t work and route them to the migrate-existing-column flow above. The only situation where you can clobber a column without staging is when there is genuinely no data to preserve, which is just the add-new-column flow.',
    '',
    '## Your first response',
    '',
    `Before any edits, send the user a short orientation message. Confirm setup is complete, list the skills loaded with one-line purposes, summarise the two options in your own words, and end with a clear question — *"Which would you like to do? You can name a specific table+column or describe what you're trying to protect."* Reference concrete tables/columns from \`.cipherstash/context.json\` when it helps. Mention that they can run \`${cli} status\` at any time to see where each rollout is.`,
    '',
    'Once the user answers, execute the relevant flow. Show diffs / generated SQL before applying. Pause for review at every database-mutating step.',
    '',
    '## Stop and ask the user when',
    '',
    bullet(
      "The user asks to convert a populated column in place. Explain why it doesn't work and offer the migrate-existing-column flow instead.",
    ),
    bullet(
      "A column the user names is already encrypted (`eql_v2_encrypted` udt) but with a different EQL config than they've described. This is the post-cutover re-encryption case (`stash encrypt update`, not yet shipped) — surface it instead of guessing.",
    ),
    bullet(
      'The schema migration would change the data type of a column the user has already filled.',
    ),
    bullet(
      'You discover existing partial CipherStash setup that disagrees with what the user is describing — someone else may have run `stash init` earlier with different choices.',
    ),
    '',
  ]

  return sections.join('\n')
}

/**
 * Render the planning action prompt.
 *
 * Plan-mode tells the agent its task is to produce a reviewable plan file
 * at `.cipherstash/plan.md` — no schema edits, no migrations, no `db push`,
 * no `encrypt *` mutations during this phase. Read-only inspection
 * (`stash status`, `stash db status`, schema grep, file reads) is fine.
 *
 * Dispatches by `ctx.planStep`:
 *
 *   `'rollout'` (default) — schema-add + dual-write code + db push.
 *                            Plan stops at the deploy gate.
 *   `'cutover'`           — backfill + cutover + drop. Pre-condition:
 *                            `dual_writing` recorded for the targeted
 *                            columns.
 *   `'complete'`          — full lifecycle in one document. Used for the
 *                            `--complete-rollout` escape hatch (databases
 *                            without a deployed application to gate on).
 */
export function renderPlanPrompt(ctx: SetupPromptContext): string {
  const step: PlanStep = ctx.planStep ?? 'rollout'

  switch (step) {
    case 'rollout':
      return renderRolloutPlanPrompt(ctx)
    case 'cutover':
      return renderCutoverPlanPrompt(ctx)
    case 'complete':
      return renderCompletePlanPrompt(ctx)
  }
}

function planSharedHeader(ctx: SetupPromptContext, title: string): string[] {
  return [
    title,
    '',
    `Integration: \`${ctx.integration}\` · Package manager: \`${ctx.packageManager}\``,
    '',
  ]
}

function planSharedSetupBlock(ctx: SetupPromptContext): string[] {
  const cli = runnerCommand(ctx.packageManager, 'stash')
  return [
    '## Where am I?',
    '',
    `Run \`${cli} status\` first. It tells you which columns are mid-rollout, which have been deployed, and what's left. Re-read it as you go — never plan blind.`,
    '',
    '## What `stash init` already did',
    '',
    ...setupChecklist(ctx),
    '',
    '## Skills loaded',
    '',
    `Reusable rules and worked examples live in ${rulesLocation(ctx.handoff)}:`,
    '',
    renderSkillIndex(ctx.installedSkills),
    '',
    'Read the skills before answering API or pattern questions. The doctrine in `AGENTS.md` (or its inlined equivalent) covers the invariants that apply regardless of which flow you take — never log plaintext, never `.notNull()` on creation, etc.',
    '',
  ]
}

function planSharedNotDoBlock(ctx: SetupPromptContext): string[] {
  const cli = runnerCommand(ctx.packageManager, 'stash')
  return [
    '## What you must NOT do',
    '',
    bullet(
      'Edit schema files, application code, or migration files. The plan describes future changes — it does not perform them.',
    ),
    bullet(
      `Run \`${cli} db push\`, \`${cli} encrypt backfill\`, \`${cli} encrypt cutover\`, \`${cli} encrypt drop\`, \`${cli} db activate\`, or any other state-mutating command.`,
    ),
    bullet(
      'Run schema migrations (`drizzle-kit migrate`, `supabase migration up`, `prisma migrate`, etc.).',
    ),
    bullet(
      'Modify the placeholder encryption client beyond what is required to read it.',
    ),
    '',
    `Read-only commands (\`${cli} status\`, \`${cli} db status\`, file reads, greps, \`${cli} doctor\` if available) are fine and encouraged — the plan is more useful when grounded in the actual current state.`,
    '',
  ]
}

function planSharedStopAndAsk(): string[] {
  return [
    '## Stop and ask the user when',
    '',
    bullet(
      "The user asks to convert a populated column in place. Explain why it doesn't work and offer the migrate-existing-column flow instead.",
    ),
    bullet(
      "A column the user names is already encrypted (`eql_v2_encrypted` udt) but with a different EQL config than they've described. This is the post-cutover re-encryption case (`stash encrypt update`, not yet shipped) — surface it in the plan as a flagged risk.",
    ),
    bullet(
      'You discover existing partial CipherStash setup that disagrees with what the user is describing — someone else may have run `stash init` earlier with different choices. Note this in the plan and ask the user to clarify before writing prescriptive steps.',
    ),
    bullet(
      "The user names columns that don't appear in `.cipherstash/context.json` or in the schema files you can see. Confirm the names rather than guessing.",
    ),
    '',
  ]
}

function planSummaryBlockExample(step: PlanStep): string {
  return [
    '  ```',
    '  <!-- cipherstash:plan-summary',
    '  {',
    `    "step": "${step}",`,
    '    "columns": [',
    '      {"table": "<table_name>", "column": "<column_name>", "path": "new" | "migrate"}',
    '    ]',
    '  }',
    '  -->',
    '  ```',
  ].join('\n')
}

/** Plan template for the encryption-rollout step (schema-add + dual-write). */
function renderRolloutPlanPrompt(ctx: SetupPromptContext): string {
  const cli = runnerCommand(ctx.packageManager, 'stash')

  const sections: string[] = [
    ...planSharedHeader(
      ctx,
      '# CipherStash setup — write an encryption rollout plan',
    ),
    `\`${cli} plan\` runs the planning phase for the **encryption rollout** — your job is to produce a reviewable plan at \`${PLAN_REL_PATH}\` that covers everything the user must land in their repo and deploy to production before any historical data can be backfilled. **Do not** make code or schema changes here; do not run mutating CLI commands. Read-only inspection is encouraged.`,
    '',
    `The encryption-cutover plan (backfill → switch reads to encrypted → drop plaintext) is a separate plan written by re-running \`${cli} plan\` after dual-writes are live in production. Stay in scope.`,
    '',
    ...planSharedSetupBlock(ctx),
    '## What this plan covers',
    '',
    "Two paths, depending on whether the column already exists:",
    '',
    bullet(
      '**Add a new encrypted column** — single deploy, no rollout/cutover split. Declared encrypted from the start.',
    ),
    bullet(
      '**Encryption rollout for an existing column** — the encrypted twin column, the application-side dual-write code, and `stash db push` (writes pending). All of this lands in one PR; the user deploys it; `cs_migrations` records `dual_writing` the next time backfill is invoked.',
    ),
    '',
    "Converting a populated column in place is **not** supported — any \"just swap the type\" approach corrupts data. If the user asks for that, the plan must explain why and route them to the encryption-rollout flow.",
    '',
    '## Your task: produce the rollout plan file',
    '',
    `Write \`${PLAN_REL_PATH}\` covering, for each table+column the user wants to protect:`,
    '',
    bullet(
      '**A machine-readable summary block at the very top of the file**, before any heading or prose. `stash impl` parses this to render a confirmation panel before launching implementation. Use this exact shape (valid JSON, single block, no other content inside the comment):',
    ),
    '',
    planSummaryBlockExample('rollout'),
    '',
    `  \`step\` is \`"rollout"\` for this plan. \`path\` is \`"new"\` for additive columns (no plaintext predecessor) and \`"migrate"\` for columns that already exist with live data. Keep the block in sync with the prose; if you revise the plan, regenerate the summary.`,
    '',
    'Then, the prose plan covers:',
    '',
    bullet(
      "The table and column names (extract candidates from `.cipherstash/context.json`; if the user hasn't yet said which columns matter, ask before writing the plan).",
    ),
    bullet(
      'Which path applies per column (additive new column or encryption-rollout for an existing one). Justify briefly.',
    ),
    bullet(
      'For migrate columns: what the rollout PR contains — schema-add, `db push` (pending), and the exact dual-write code change. The dual-write definition matters: every persistence path that mutates the row writes both columns, in the same transaction, on every code branch.',
    ),
    bullet(
      `Project-specific risks. Common ones: bundler exclusion not yet configured (Next.js / webpack / Vite), top-level-await in the placeholder encryption client breaks non-Next contexts, existing partial CipherStash state (run \`${cli} db status\` and note any pre-existing encrypted columns or pending configs).`,
    ),
    bullet(
      'A "Deploy gate" section near the end of the plan that explicitly says: after the rollout PR is in production and serving real traffic, the user runs `' +
        cli +
        ' status` to confirm, then `' +
        cli +
        ' plan` again — at that point the CLI will detect dual-writes and produce a separate cutover plan covering backfill, read-path switch, and drop.',
    ),
    bullet(
      "Open questions for the user — anything you can't determine from the schema, context.json, or the skills.",
    ),
    '',
    `After writing the plan, also offer to copy it into \`docs/plans/cipherstash-encryption-rollout.md\` if the project has a \`docs/plans/\` directory — many teams version their plans alongside the code. Don't copy without asking. If \`docs/plans/\` does not exist, leave the plan at \`${PLAN_REL_PATH}\` and don't create the directory.`,
    '',
    ...planSharedNotDoBlock(ctx),
    '## Your first response',
    '',
    `Send the user a short orientation message before writing anything. Confirm setup is complete, list the skills loaded with one-line purposes, explain what an encryption rollout is in your own words, and end with a clear question — *"Which table(s) and column(s) would you like the rollout plan to cover? You can name them or describe what you're trying to protect."* Reference concrete tables/columns from \`.cipherstash/context.json\` when it helps.`,
    '',
    `Once the user answers, write \`${PLAN_REL_PATH}\`. Show the plan in chat as well so the user can react inline. After the plan is approved, tell the user to run \`${cli} impl\` to execute it.`,
    '',
    ...planSharedStopAndAsk(),
  ]

  return sections.join('\n')
}

/** Plan template for the encryption-cutover step (backfill + cutover + drop). */
function renderCutoverPlanPrompt(ctx: SetupPromptContext): string {
  const cli = runnerCommand(ctx.packageManager, 'stash')

  const sections: string[] = [
    ...planSharedHeader(
      ctx,
      '# CipherStash setup — write an encryption cutover plan',
    ),
    `\`${cli} plan\` detected that dual-writes are recorded as live in \`cs_migrations\` for at least one column. Your job is to produce a reviewable plan at \`${PLAN_REL_PATH}\` covering the **encryption cutover** — backfilling historical rows, switching reads through the encryption client, and dropping the old plaintext column. **Do not** make code or schema changes here; do not run mutating CLI commands. Read-only inspection is encouraged.`,
    '',
    'The encryption rollout (schema-add + dual-write code + `db push`) is assumed already deployed to production. If the prose ends up describing dual-write code edits, you are off-scope — re-anchor on what cutover-step work remains.',
    '',
    ...planSharedSetupBlock(ctx),
    '## What this plan covers',
    '',
    'For each column whose dual-writes are live in production:',
    '',
    bullet(
      '**Backfill.** Encrypt the historical rows that pre-date the rollout deploy. Resumable; chunked; SIGINT-safe.',
    ),
    bullet(
      '**Schema rename and re-push.** Update the schema declaration to put the encrypted form under its final column name; `stash db push` registers the renamed pending config.',
    ),
    bullet(
      '**Cutover.** A single transaction renames `<col>` → `<col>_plaintext`, `<col>_encrypted` → `<col>`, and promotes the pending EQL config to active.',
    ),
    bullet(
      '**Read path.** Application reads of `<col>` now return ciphertext until the read path decrypts via the encryption client. The plan must specify what changes per read site.',
    ),
    bullet(
      '**Remove dual-writes.** The plaintext column is now `<col>_plaintext` and is no longer authoritative. Delete the dual-write code paths.',
    ),
    bullet(
      '**Drop plaintext.** `stash encrypt drop` emits a migration that removes `<col>_plaintext`. Apply with the project\'s normal migration tooling.',
    ),
    '',
    '## Your task: produce the cutover plan file',
    '',
    `Write \`${PLAN_REL_PATH}\` covering, for each column scheduled for cutover:`,
    '',
    bullet(
      '**A machine-readable summary block at the very top of the file**, before any heading or prose. `stash impl` parses this to render a confirmation panel and to enforce the deploy gate (it refuses cutover-step plans without a recorded `dual_writing` event). Use this exact shape:',
    ),
    '',
    planSummaryBlockExample('cutover'),
    '',
    `  \`step\` is \`"cutover"\` for this plan. \`path\` should be \`"migrate"\` for every column (cutover only applies to migrate columns; new columns never went through dual-writing). Keep the block in sync with the prose.`,
    '',
    'Then the prose plan covers:',
    '',
    bullet(
      'For each column: backfill ordering (which to do first; any large tables that should run during low-traffic windows), the exact `' +
        cli +
        ' encrypt backfill` invocation with concrete `--table` / `--column` values.',
    ),
    bullet(
      'The schema-edit + `db push` step, with the exact rename pattern (drop `_encrypted` suffix on the encrypted column, switch the original column declaration off `text`/`varchar` and onto the encrypted type).',
    ),
    bullet(
      'The cutover invocation per column: `' +
        cli +
        ' encrypt cutover --table <T> --column <c>`.',
    ),
    bullet(
      'Read-path code changes: every site that reads `<col>` from this table must decrypt via the encryption client. Enumerate the sites you can find via grep so the user can verify nothing was missed.',
    ),
    bullet(
      'Removal of the dual-write code from the persistence layer.',
    ),
    bullet(
      'The drop invocation: `' +
        cli +
        ' encrypt drop --table <T> --column <c>`, plus the schema-migration apply step that follows.',
    ),
    bullet(
      `Risks specific to cutover: row-count for the backfill (use \`${cli} db status\` to estimate if helpful), tables under heavy write load (cutover holds a brief lock on the rename), application code that constructs SQL by string (those reads won't transparently decrypt).`,
    ),
    bullet(
      "Open questions for the user — anything you can't determine from the schema, context.json, or the skills.",
    ),
    '',
    `After writing the plan, also offer to copy it into \`docs/plans/cipherstash-encryption-cutover.md\` if the project has a \`docs/plans/\` directory. Don't copy without asking.`,
    '',
    ...planSharedNotDoBlock(ctx),
    '## Your first response',
    '',
    `Send the user a short orientation message before writing anything. Confirm setup is complete, name the columns whose dual-writes are recorded as live (you can derive this from \`${cli} status\`), and ask the user — *"Which of these would you like the cutover plan to cover? Any preferences on ordering, e.g. small tables before large ones?"*`,
    '',
    `Once the user answers, write \`${PLAN_REL_PATH}\`. Show the plan in chat as well so the user can react inline. After the plan is approved, tell the user to run \`${cli} impl\` to execute it.`,
    '',
    ...planSharedStopAndAsk(),
  ]

  return sections.join('\n')
}

/** Plan template for the complete-rollout escape hatch. */
function renderCompletePlanPrompt(ctx: SetupPromptContext): string {
  const cli = runnerCommand(ctx.packageManager, 'stash')

  const sections: string[] = [
    ...planSharedHeader(
      ctx,
      '# CipherStash setup — write a complete encryption rollout plan',
    ),
    `The user invoked \`${cli} plan --complete-rollout\`. This produces a single plan that covers the entire lifecycle — schema-add, dual-write code, backfill, cutover, drop — without the production-deploy gate that normally separates rollout from cutover.`,
    '',
    "**This is the escape hatch.** It is only safe when the database backing this project is *not* serving a deployed application — local development against a seeded DB, ephemeral test environments, sandboxes. The plan must call this out and ask the user to confirm. If they're working against a deployed app, redirect them to the staged flow (`" +
      cli +
      ' plan` without the flag) so the encryption rollout deploys before backfill runs.',
    '',
    ...planSharedSetupBlock(ctx),
    '## What this plan covers',
    '',
    'The full lifecycle for each column the user wants to protect, in order:',
    '',
    bullet(
      "**Add new encrypted columns** — declared encrypted from the start; single-deploy.",
    ),
    bullet(
      '**Migrate existing columns** — schema-add → dual-write code → `db push` → backfill → schema rename → `db push` → cutover → read-path switch → remove dual-write code → drop plaintext. No deploy gate between rollout and cutover steps because there is no deployed application to gate on.',
    ),
    '',
    '## Your task: produce the complete-rollout plan file',
    '',
    `Write \`${PLAN_REL_PATH}\` with:`,
    '',
    bullet(
      '**A machine-readable summary block at the very top of the file.** Use this exact shape:',
    ),
    '',
    planSummaryBlockExample('complete'),
    '',
    `  \`step\` is \`"complete"\` for this plan. \`path\` is \`"new"\` or \`"migrate"\` per column.`,
    '',
    bullet(
      "An explicit warning at the top of the prose: this plan skips the production-deploy gate; backfill will run against rows that may not have been seen by deployed dual-write code. Confirm with the user that no deployed application is writing to this database before they run `" +
        cli +
        ' impl`.',
    ),
    bullet(
      'For migrate columns: the full step list with the exact CLI invocations (`' +
        cli +
        ' encrypt backfill`, `cutover`, `drop`) and concrete `--table` / `--column` values.',
    ),
    bullet(
      'For new columns: the additive single-deploy walkthrough.',
    ),
    bullet(
      `Project-specific risks. Common ones: bundler exclusion not yet configured (Next.js / webpack / Vite), top-level-await in the placeholder encryption client breaks non-Next contexts, existing partial CipherStash state (run \`${cli} db status\` and note any pre-existing encrypted columns or pending configs).`,
    ),
    bullet(
      "Open questions for the user — anything you can't determine from the schema, context.json, or the skills.",
    ),
    '',
    `After writing the plan, also offer to copy it into \`docs/plans/cipherstash-encryption.md\` if the project has a \`docs/plans/\` directory. Don't copy without asking.`,
    '',
    ...planSharedNotDoBlock(ctx),
    '## Your first response',
    '',
    `Send the user a short orientation message before writing anything. Confirm setup is complete, **explicitly name that this is the escape-hatch flow that skips the production-deploy gate**, and end with — *"Which table(s) and column(s) would you like to encrypt end-to-end? And can you confirm this database isn't backing a deployed application?"*`,
    '',
    `Once the user answers, write \`${PLAN_REL_PATH}\`. Show the plan in chat as well so the user can react inline. After the plan is approved, tell the user to run \`${cli} impl\` to execute it.`,
    '',
    ...planSharedStopAndAsk(),
  ]

  return sections.join('\n')
}
