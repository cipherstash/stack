/**
 * Non-interactive context detection, shared so every resolver gates the same
 * way instead of each re-deriving it.
 */

/**
 * Provider-specific markers for CI systems that don't reliably set `CI=true`
 * (Jenkins, Azure Pipelines/`TF_BUILD`, TeamCity, …). GitHub Actions and GitLab
 * both DO set `CI=true`, so their vars here are belt-and-suspenders. Detected by
 * presence of any non-empty value.
 */
export const CI_PROVIDER_ENV_VARS = [
  'GITHUB_ACTIONS',
  'GITLAB_CI',
  'CIRCLECI',
  'TRAVIS',
  'BUILDKITE',
  'JENKINS_URL',
  'TEAMCITY_VERSION',
  'TF_BUILD', // Azure Pipelines
  'APPVEYOR',
  'DRONE',
  'BITBUCKET_BUILD_NUMBER',
  'CODEBUILD_BUILD_ID',
] as const

/**
 * Every env var {@link isCiEnv} consults. Exported so tests can neutralize all
 * CI signals hermetically (clearing only `CI` leaves ambient provider vars — a
 * real `GITHUB_ACTIONS=true` in this repo's own CI — able to flip the result).
 */
export const CI_ENV_VARS = [
  'CI',
  'CONTINUOUS_INTEGRATION',
  ...CI_PROVIDER_ENV_VARS,
] as const

/**
 * True when `CI` is set to a truthy spelling (`1`/`true`) — the near-universal
 * marker, set by GitHub Actions, GitLab, CircleCI, and most others. This is the
 * NARROW check that governs interactive prompting: the region resolver
 * (`commands/auth/region.ts`), the DATABASE_URL resolver (`config/database-url.ts`),
 * and {@link isInteractive}. It is intentionally conservative about suppressing a
 * prompt — a developer whose shell happens to export a provider marker like
 * `JENKINS_URL` should still get prompted. Telemetry uses the broader
 * {@link isCiEnvBroad} instead, where erring toward "don't collect" is safer.
 */
export function isCiEnv(): boolean {
  const ciVar = process.env.CI?.trim()
  return ciVar !== undefined && /^(1|true)$/i.test(ciVar)
}

/**
 * True in CI, detected broadly: {@link isCiEnv} plus `CONTINUOUS_INTEGRATION` and
 * the {@link CI_PROVIDER_ENV_VARS} markers for systems that don't set `CI`
 * (Jenkins, TeamCity, Azure Pipelines, …). Used ONLY for telemetry auto-disable,
 * where a false positive merely skips collection — unlike prompt gating, where a
 * false positive breaks an interactive command. Keep it separate from
 * {@link isCiEnv} so broadening CI-for-telemetry never changes prompt behavior.
 */
export function isCiEnvBroad(): boolean {
  if (isCiEnv()) return true
  if (process.env.CONTINUOUS_INTEGRATION?.trim()) return true
  return CI_PROVIDER_ENV_VARS.some((name) => Boolean(process.env[name]?.trim()))
}

/**
 * Coarse classification of who invoked the CLI, for anonymous telemetry. A
 * heuristic, not a guarantee: it recognises the major coding-agent harnesses by
 * an env var each one sets, and otherwise falls back to whether stdin is a TTY.
 * Only the fixed label ever leaves the machine (see the telemetry allowlist) —
 * never the underlying env value, some of which carry session/trace IDs. Read
 * the numbers as a lower bound on agent usage: a harness without a known marker
 * lands in `interactive`/`non-interactive`.
 */
export type CallerKind =
  | 'claude-code'
  | 'cursor'
  | 'codex'
  | 'editor'
  | 'interactive'
  | 'non-interactive'

/**
 * Known coding-agent harnesses, each recognised by an env var it sets in the
 * shell it drives. Ordered most-specific first; the first match wins. Extend
 * this as new harnesses appear — every `kind` must stay a fixed, non-identifying
 * string, because that label (not the env value) is what telemetry emits.
 */
const AGENT_MARKERS: ReadonlyArray<{
  readonly kind: CallerKind
  readonly envVars: readonly string[]
}> = [
  // Claude Code sets CLAUDECODE=1; CLAUDE_CODE_ENTRYPOINT is a backup signal.
  { kind: 'claude-code', envVars: ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT'] },
  // Cursor's agent/terminal exports a per-session trace id.
  { kind: 'cursor', envVars: ['CURSOR_TRACE_ID'] },
  // OpenAI Codex CLI runs commands in a sandbox that exports CODEX_SANDBOX.
  { kind: 'codex', envVars: ['CODEX_SANDBOX'] },
]

/**
 * Every env var {@link resolveCaller} consults. Exported so tests can neutralize
 * all caller signals hermetically — this repo's own agent harness sets some of
 * these ambiently, which would otherwise flip the result.
 */
export const CALLER_ENV_VARS = [
  ...AGENT_MARKERS.flatMap((m) => m.envVars),
  'TERM_PROGRAM',
] as const

/**
 * Classify the caller. Confirmed agent harnesses win first; then a VS Code-family
 * editor terminal (`TERM_PROGRAM=vscode`, which Cursor also sets, so it is checked
 * after Cursor and kept distinct because it may be a human in an editor); then the
 * plain TTY heuristic.
 */
export function resolveCaller(): CallerKind {
  for (const marker of AGENT_MARKERS) {
    if (marker.envVars.some((name) => Boolean(process.env[name]?.trim()))) {
      return marker.kind
    }
  }
  if (process.env.TERM_PROGRAM?.trim().toLowerCase() === 'vscode') {
    return 'editor'
  }
  return process.stdin.isTTY ? 'interactive' : 'non-interactive'
}

/**
 * True when it's safe to show an interactive clack prompt: stdin is a TTY and
 * we're not in CI. Every prompt gate (the DATABASE_URL resolver, the config
 * scaffolder, the Supabase install-mode selector) must decide this the same
 * way, so they all call here rather than re-deriving `isTTY && !CI` inline and
 * drifting apart.
 */
export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY) && !isCiEnv()
}
