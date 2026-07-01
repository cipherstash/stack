import { describe, expect, it } from 'vitest'
import { run } from '../helpers/run.js'

/**
 * E2E coverage for the runner-aware help rendering. The smoke suite
 * already verifies the help is rendered; this file specifically asserts
 * that the correct package-manager runner (`npx` / `bunx` / `pnpm dlx` /
 * `yarn dlx`) flows from `npm_config_user_agent` through
 * `detectPackageManager` → `runnerCommand` into the Usage line and
 * Examples.
 *
 * Detection itself is unit-tested in
 * `src/commands/init/__tests__/utils.test.ts`. These E2E tests close the
 * gap between "the helper works in isolation" and "the rendered HELP
 * actually surfaces what the helper produces".
 */

const cases = [
  { ua: '', label: 'npx' }, // empty UA — falls back to lockfile/npm
  { ua: 'bun/1.0.0', label: 'bunx' },
  { ua: 'pnpm/9.0.0', label: 'pnpm dlx' },
  { ua: 'yarn/4.0.0', label: 'yarn dlx' },
] as const

describe('--help — runner-aware Usage + Examples', () => {
  it.each(
    cases,
  )('with npm_config_user_agent=$ua, renders "$label stash"', async ({
    ua,
    label,
  }) => {
    const r = await run(['--help'], { env: { npm_config_user_agent: ua } })
    expect(r.exitCode).toBe(0)
    // Usage line must use the right runner. The leader is stable
    // (`messages.cli.usagePrefix === 'Usage: '`) so we assert on the
    // suffix the renderer composes at runtime.
    expect(r.output).toContain(`Usage: ${label} stash`)
    // At least one of the Examples lines must surface the same runner.
    expect(r.output).toContain(`${label} stash init`)
    expect(r.output).toContain(`${label} stash db install`)
  })
})

describe('auth — runner-aware Usage + Examples', () => {
  it.each(
    cases,
  )('with npm_config_user_agent=$ua, renders "$label stash auth"', async ({
    ua,
    label,
  }) => {
    // `auth` with no subcommand prints the auth HELP and exits 0.
    const r = await run(['auth'], { env: { npm_config_user_agent: ua } })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain(`Usage: ${label} stash auth`)
    expect(r.output).toContain(`${label} stash auth login`)
  })
})
