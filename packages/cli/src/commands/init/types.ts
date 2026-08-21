import type { AgentEnvironment } from './detect-agents.js'
import type { PlanStep } from './lib/parse-plan.js'
import type { PackageManager } from './utils.js'

export type Integration = 'drizzle' | 'supabase' | 'prisma-next' | 'postgresql'

/**
 * The integration flags `stash init` accepts (`--supabase`, `--drizzle`,
 * `--prisma`). They are not mutually exclusive — `stash init --drizzle
 * --supabase` is a real, accepted invocation for a Drizzle project on Supabase.
 */
export type ProviderKey = 'supabase' | 'drizzle' | 'prisma'

/**
 * The {@link Integration} each flag selects. `--prisma` is the odd one out: the
 * flag is short for consistency with `--supabase` / `--drizzle`, but the
 * integration it selects is Prisma Next (see providers/prisma.ts).
 */
export const PROVIDER_KEY_INTEGRATION: Readonly<
  Record<ProviderKey, Integration>
> = {
  supabase: 'supabase',
  drizzle: 'drizzle',
  prisma: 'prisma-next',
}

export type DataType = 'string' | 'number' | 'boolean' | 'date' | 'json'

/**
 * A concrete EQL v3 domain factory name on the `types` namespace
 * (`@cipherstash/stack/eql/v3`). v3 has no chainable capability tuners — a
 * column's query capabilities are fixed by which domain you pick. The scaffold
 * offers the subset below; the full numeric/date lattice
 * (Smallint/Bigint/Numeric/Real/Double/Timestamp) is left to the user's real
 * schema files, exactly as `pgTypeToDataType` collapses those types today.
 */
export type V3Domain =
  | 'Text'
  | 'TextEq'
  | 'TextOrd'
  | 'TextMatch'
  | 'TextSearch'
  | 'Integer'
  | 'IntegerEq'
  | 'IntegerOrd'
  | 'Date'
  | 'DateEq'
  | 'DateOrd'
  | 'Boolean'
  | 'Json'

export interface ColumnDef {
  name: string
  domain: V3Domain
}

export interface SchemaDef {
  tableName: string
  columns: ColumnDef[]
}

export type HandoffChoice =
  | 'claude-code'
  | 'codex'
  | 'agents-md'
  | 'lovable'
  | 'wizard'

/**
 * Whether the handoff agent should produce a plan first (`plan`) or go
 * straight to implementation (`implement`). `plan` is the default — it
 * gives the user a reviewable plan file at `.cipherstash/plan.md` before
 * any code or schema changes happen.
 */
export type InitMode = 'plan' | 'implement'

/**
 * How the per-integration skills reached (or failed to reach) the project.
 * Threaded into `context.json` and the setup prompt so both describe what
 * actually happened, not what the handoff hoped for:
 *
 *   installed — copied into a skills directory (`.claude/skills`,
 *               `.codex/skills`)
 *   inlined   — bodies written into AGENTS.md under "## Skill references"
 *               (the editor-agent handoff, and the Codex fallback for an
 *               unwritable `.codex/` — #736)
 *   failed    — bundled skills that ended up nowhere (destination
 *               unwritable with no inline fallback, or AGENTS.md itself
 *               unwritable)
 *
 * Lives here rather than in `lib/write-context.ts` (where it started) so
 * `InitState` can carry one without a circular import.
 */
export interface SkillsDelivery {
  installed: string[]
  inlined: string[]
  failed: string[]
}

/** Merge two deliveries, de-duplicating and keeping a stable order.
 *
 *  Exists because skills now reach a project in more than one hop: `stash
 *  init` installs them first thing, and a later `stash plan` / `stash impl`
 *  handoff installs or inlines its own set. `writeArtifacts` used to
 *  OVERWRITE `context.json.installedSkills` with just the current hop's
 *  result, so `stash plan --target agents-md` (which installs no
 *  directories) reset the field to `[]` on a project that had them — the
 *  same false-empty state #923 is about, reached one command later.
 *
 *  A name that failed in one hop and succeeded in another counts as
 *  delivered: `failed` is filtered against the merged successes so the
 *  record never reports a skill as both.
 */
export function mergeSkillsDelivery(
  a: SkillsDelivery | undefined,
  b: SkillsDelivery,
): SkillsDelivery {
  const dedupe = (xs: string[]) => [...new Set(xs)]
  const installed = dedupe([...(a?.installed ?? []), ...b.installed])
  const inlined = dedupe([...(a?.inlined ?? []), ...b.inlined])
  const delivered = new Set([...installed, ...inlined])
  const failed = dedupe([...(a?.failed ?? []), ...b.failed]).filter(
    (name) => !delivered.has(name),
  )
  return { installed, inlined, failed }
}

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
  /** True when the pending migration was ALREADY on disk — a re-run of `stash
   *  init --supabase`, or a project whose migration came from a standalone
   *  `stash eql migration --supabase`. Refines `eqlMigrationPending`, never
   *  replaces it: the state of the world is the same either way (a migration
   *  exists, it has not been applied) and so is the apply guidance, so the
   *  incompleteness check must keep reading `eqlMigrationPending` alone. All
   *  this changes is the summary's verb — "already present" rather than
   *  "generated", which was a claim about work this run did not do. */
  eqlMigrationAlreadyPresent?: boolean
  /** Detected ORM / framework integration. Set by build-schema. */
  integration?: Integration
  /** Schema definitions written to the encryption client. Carries every
   *  table the user picked during introspection (or the single placeholder
   *  for empty databases). The generated client file is still the canonical
   *  source for the full set of column domains. */
  schemas?: SchemaDef[]
  /** Names of env keys observed in `.env*` files at init time. Never the
   *  values. Set by build-schema (so the baseline context.json has them);
   *  read by the handoff steps without re-scanning. */
  envKeys?: string[]
  /** Available coding agents in the user's environment. Set by the
   *  install-skills step (the first thing `stash init` runs) and reused by
   *  gather-context rather than re-walking `PATH`. */
  agents?: AgentEnvironment
  /** Where the per-integration skills ended up. Accumulated across every hop
   *  that delivers them — the init step, then any later handoff — and read by
   *  `buildContextFile` so `context.json` reports the union rather than the
   *  most recent hop. */
  skills?: SkillsDelivery
  /** Validated `--target` from `stash init`. On `init` this selects the
   *  skills destination ONLY; it does not perform a handoff the way
   *  `plan --target` / `impl --target` do. Absent means "auto-detect". */
  targetFlag?: HandoffChoice
  /** What the user picked at the "how to proceed" step. */
  handoff?: HandoffChoice
  /** True when the handoff step actually launched an agent process
   *  (`claude` / `codex` / the wizard), regardless of its exit code.
   *  Deferred handoffs — AGENTS.md, or a CLI target that isn't installed —
   *  leave it unset. `stash plan` uses this to tell "the agent ran but
   *  wrote no plan" (an error) from "the plan is written later, when the
   *  user drives their agent" (#738). */
  agentLaunched?: boolean
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
  /**
   * Referrer / display identity, NOT a routing signal. A multi-flag run joins
   * every matched flag alphabetically (`stash init --drizzle --supabase` →
   * `'drizzle-supabase'`), matching the referrer `stash auth login --drizzle
   * --supabase` records, and `authenticateStep` passes it straight to
   * `login()`. Because that combined string equals no single flag name, code
   * that branched on `provider.name === 'supabase'` fell through on every
   * combined run — read {@link InitProvider.selected} instead.
   */
  name: string
  /**
   * The integration flags the user actually passed, in `PROVIDER_KEYS` order
   * (`resolveProvider`, init/index.ts). This is the capability signal: every
   * step that asks "is this a Supabase run?" tests membership here rather than
   * parsing `name`, so combined flags keep working and `name` stays free to
   * carry whatever the referrer needs.
   */
  selected: readonly ProviderKey[]
  introMessage: string
  getNextSteps(state: InitState, pm: PackageManager): string[]
}

export class CancelledError extends Error {
  constructor() {
    super('cancelled')
    this.name = 'CancelledError'
  }
}
