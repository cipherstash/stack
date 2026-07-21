import type { AgentEnvironment } from './detect-agents.js'
import type { PlanStep } from './lib/parse-plan.js'
import type { PackageManager } from './utils.js'

export type Integration = 'drizzle' | 'supabase' | 'prisma-next' | 'postgresql'

export type DataType = 'string' | 'number' | 'boolean' | 'date' | 'json'

export type SearchOp = 'equality' | 'orderAndRange' | 'freeTextSearch'

export interface ColumnDef {
  name: string
  dataType: DataType
  searchOps: SearchOp[]
}

export interface SchemaDef {
  tableName: string
  columns: ColumnDef[]
}

export type HandoffChoice = 'claude-code' | 'codex' | 'agents-md' | 'wizard'

/**
 * Whether the handoff agent should produce a plan first (`plan`) or go
 * straight to implementation (`implement`). `plan` is the default — it
 * gives the user a reviewable plan file at `.cipherstash/plan.md` before
 * any code or schema changes happen.
 */
export type InitMode = 'plan' | 'implement'

export interface InitState {
  authenticated?: boolean
  /** Region passed via `--region` / `STASH_REGION`. Consumed by the
   *  authenticate step to skip the interactive region picker. */
  regionFlag?: string
  /** Resolved DATABASE_URL. Set by resolve-database; threaded into every
   *  downstream step that needs DB access. Never logged or echoed. */
  databaseUrl?: string
  clientFilePath?: string
  schemaGenerated?: boolean
  /** True when the encryption schema was sourced from live DB introspection
   *  rather than the placeholder. Drives messaging in the action prompt. */
  schemaFromIntrospection?: boolean
  stackInstalled?: boolean
  /** True when the `stash` CLI is in the project's devDependencies. */
  cliInstalled?: boolean
  /** True when EQL was installed (or already-installed) by install-eql —
   *  i.e. the extension is actually present in the target database. */
  eqlInstalled?: boolean
  /** True when install-eql GENERATED a migration file but did not apply it
   *  (the Drizzle v3 path, or Supabase `--migration` mode). EQL is not in the
   *  database yet — the user applies it with `drizzle-kit migrate` (or their
   *  Supabase migration workflow). Distinct from `eqlInstalled` so the init
   *  summary reports "migration generated, apply it" instead of a false
   *  "installed" or a spurious "setup incomplete". */
  eqlMigrationPending?: boolean
  /** Detected ORM / framework integration. Set by build-schema. */
  integration?: Integration
  /** Schema definitions written to the encryption client. Carries every
   *  table the user picked during introspection (or the single placeholder
   *  for empty databases). The generated client file is still the canonical
   *  source for the full set of column types and search ops. */
  schemas?: SchemaDef[]
  /** Names of env keys observed in `.env*` files at init time. Never the
   *  values. Set by build-schema (so the baseline context.json has them);
   *  read by the handoff steps without re-scanning. */
  envKeys?: string[]
  /** Available coding agents in the user's environment. Set by detect-agents. */
  agents?: AgentEnvironment
  /** What the user picked at the "how to proceed" step. */
  handoff?: HandoffChoice
  /** Whether the handoff is producing a plan or executing one. Set by the
   *  command itself: `stash plan` always sets `'plan'`, `stash impl` always
   *  sets `'implement'`. */
  mode?: InitMode
  /** Which step of the encryption rollout the plan should target. Set by
   *  `stash plan` after reading `cs_migrations` (or when the user passes
   *  `--complete-rollout`). Drives the plan-prompt template selection. Not
   *  meaningful in implement mode — `stash impl` reads the step from the
   *  on-disk plan-summary block instead. Defaults to `'rollout'` when the
   *  CLI has nothing else to go on (fresh project, no DB connectivity). */
  planStep?: PlanStep
  /** Whether the user queries encrypted data via CipherStash Proxy. Captured in stash init. SDK users default to false; setting true makes prompts/skills include `stash db push` steps. */
  usesProxy?: boolean
}

/**
 * A step that runs as part of the `stash init` pipeline. The init
 * pipeline owns the `InitProvider` (intro copy, provider-specific
 * defaults) and threads it into every step. Some init steps consult it
 * (e.g. `authenticateStep` reads `provider.name` for telemetry) so the
 * argument is required at the type level — calling
 * `authenticateStep.run(state)` without a provider would crash.
 */
export interface InitStep {
  id: string
  name: string
  run(state: InitState, provider: InitProvider): Promise<InitState>
}

/**
 * A step that runs after init has finished — invoked by `stash plan` and
 * `stash impl` to drive the agent handoff. These steps don't have an
 * `InitProvider` available (init owns that abstraction) and don't need
 * one, so the type intentionally omits it. Keeping `InitStep` and
 * `HandoffStep` distinct prevents callers from accidentally invoking
 * init-only steps from the post-init flow.
 */
export interface HandoffStep {
  id: string
  name: string
  run(state: InitState): Promise<InitState>
}

export interface InitProvider {
  name: string
  introMessage: string
  getNextSteps(state: InitState, pm: PackageManager): string[]
}

export class CancelledError extends Error {
  constructor() {
    super('cancelled')
    this.name = 'CancelledError'
  }
}
