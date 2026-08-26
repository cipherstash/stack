import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * Every `neon dist` invoked through `pnpm exec` must pass `-n <crate name>`,
 * and that name must be the crate actually being built.
 *
 * `neon dist` locates the compiled cdylib in the cargo log by crate name, and
 * defaults that name to `basename($npm_package_name)` — see
 * `@neon-rs/cli/index.js`, `ensureDefined(process.env['npm_package_name'],
 * '$npm_package_name')`. That variable is populated by a package-script run and
 * NOT by `pnpm exec`, so the default is unavailable precisely where this
 * repository needs the command: `_build-ffi-artifacts.yml` calls the binary
 * directly in order to pass `-o platforms/<platform>/index.node`, because a
 * bare `neon dist` writes `./index.node` — the `debug:` fallback in `load.cts`,
 * which is right for local development and wrong for a published tarball.
 *
 * Upstream never met this failure, which is why it was not inherited along with
 * the rest of the build: `postcargo-build` and `postzig-build` run `neon dist`
 * as npm lifecycle scripts, where the variable exists. The first direct call is
 * this repository's, and it failed all six platform legs with
 * `error: $npm_package_name is not defined`.
 *
 * Three ways for that to come back:
 *
 *   - the flag is dropped while editing the surrounding shell, and every
 *     platform fails again;
 *   - the crate is renamed and the flag is not, which does NOT fail loudly in
 *     the same way — `neon dist` finds no matching artifact in the log, and the
 *     mode it fails in is a build that produced nothing rather than a build
 *     that errored;
 *   - a second `neon dist` is added to a step that already has a correct one,
 *     and inherits none of its flags.
 *
 * The third is why the scan is per INVOCATION rather than per step. Matching
 * once over a step body answers for whichever call came first, and the `-n` it
 * finds need not belong to a `neon dist` at all — `echo -n protect-ffi` on an
 * earlier line satisfied it. The last two `it` blocks below hold the scanner
 * itself to that, since no workflow in the tree exercises either shape.
 *
 * Discovery, not a list: any workflow that grows a `neon dist` call is covered
 * the day it lands.
 */

/** The crate whose cdylib becomes `index.node`. */
function crateName() {
  const toml = readFileSync(
    join(REPO_ROOT, 'packages/protect-ffi/crates/protect-ffi/Cargo.toml'),
    'utf8',
  )
  const match = toml.match(/^\s*name\s*=\s*"([^"]+)"/m)
  if (!match)
    throw new Error('no [package] name in crates/protect-ffi/Cargo.toml')
  return match[1]
}

/** Every `run:` script in a workflow, with the job and step that carry it. */
function runSteps(workflow) {
  return Object.entries(workflow.jobs ?? {}).flatMap(([jobId, job]) =>
    (job.steps ?? [])
      .filter((step) => typeof step.run === 'string')
      .map((step) => ({
        jobId,
        name: step.name ?? '(unnamed)',
        run: step.run,
      })),
  )
}

const NEON_DIST = /pnpm\s+exec\s+neon\s+dist\b/

/**
 * Each `pnpm exec neon dist` in a run block, split out as its own command.
 *
 * Per INVOCATION, not per step, and the distinction is the whole point. A
 * single regex over the step body finds one `-n` and stops, so a step holding
 * two calls is judged by whichever came first — and worse, the flag it finds
 * need not belong to a `neon dist` at all. `sort -n` or `echo -n protect-ffi`
 * on an earlier line would satisfy a body-wide match.
 *
 * Continuations are joined first, so a newline is a real statement boundary
 * rather than a wrapped one. `||` is listed before `|` because split()
 * alternation is ordered and would otherwise cut on the first bar.
 */
function neonDistInvocations(run) {
  return run
    .replace(/\\\n\s*/g, ' ')
    .split(/\n|;|&&|\|\||\|/)
    .map((command) => command.trim())
    .filter((command) => NEON_DIST.test(command))
}

/** The `-n` / `--name` value of one command, or undefined if it carries none. */
function crateNameFlag(command) {
  return command.match(/(?:^|\s)(?:-n|--name)\s+(\S+)/)?.[1]
}

describe('neon dist through pnpm exec', () => {
  const invocations = workflowFiles().flatMap((file) =>
    runSteps(readWorkflow(file)).flatMap((step) =>
      neonDistInvocations(step.run).map((command, i) => ({
        file,
        jobId: step.jobId,
        name: step.name,
        nth: i + 1,
        command,
      })),
    ),
  )

  it('is invoked somewhere, or this guard is checking nothing', () => {
    expect(invocations.length).toBeGreaterThan(0)
  })

  it.each(invocations)(
    '$file › $jobId › $name › call $nth passes the crate name',
    ({ command }) => {
      expect(
        crateNameFlag(command),
        'neon dist needs -n; $npm_package_name is unset under pnpm exec',
      ).toBe(crateName())
    },
  )

  // The scanner's own coverage. Both of these describe a workflow that does not
  // exist yet, so nothing above would notice if the splitting regressed to a
  // body-wide match — which is what it was when this guard first landed.
  it('sees a second invocation hiding behind a correctly named first', () => {
    const run = [
      `pnpm exec neon dist -n ${crateName()} -o one < cargo.log`,
      'pnpm exec neon dist -o two < cargo.log',
    ].join('\n')

    expect(neonDistInvocations(run)).toHaveLength(2)
    expect(neonDistInvocations(run).map(crateNameFlag)).toEqual([
      crateName(),
      undefined,
    ])
  })

  it('does not count a -n belonging to another command in the same step', () => {
    const run = [
      `echo -n ${crateName()}`,
      'pnpm exec neon dist -o out < cargo.log',
    ].join('\n')

    expect(neonDistInvocations(run).map(crateNameFlag)).toEqual([undefined])
  })
})
