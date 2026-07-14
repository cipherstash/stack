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
 * True in a CI environment. `CI`/`CONTINUOUS_INTEGRATION` set to a truthy
 * spelling (`true`/`1`) covers most providers — including GitHub Actions and
 * GitLab — and {@link CI_PROVIDER_ENV_VARS} catches the ones that don't set
 * `CI`. Shared by the region resolver (`commands/auth/region.ts`), the
 * DATABASE_URL resolver (`config/database-url.ts`), and telemetry gating so they
 * all decide "is this CI?" the same way.
 */
export function isCiEnv(): boolean {
  const ciVar = process.env.CI?.trim()
  if (ciVar !== undefined && /^(1|true)$/i.test(ciVar)) return true
  if (process.env.CONTINUOUS_INTEGRATION?.trim()) return true
  return CI_PROVIDER_ENV_VARS.some((name) => Boolean(process.env[name]?.trim()))
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
