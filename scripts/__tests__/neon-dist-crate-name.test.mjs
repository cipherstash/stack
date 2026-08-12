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
 * Two ways for that to come back, hence two assertions:
 *
 *   - the flag is dropped while editing the surrounding shell, and every
 *     platform fails again;
 *   - the crate is renamed and the flag is not, which does NOT fail loudly in
 *     the same way — `neon dist` finds no matching artifact in the log, and the
 *     mode it fails in is a build that produced nothing rather than a build
 *     that errored.
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

describe('neon dist through pnpm exec', () => {
  const calls = workflowFiles().flatMap((file) =>
    runSteps(readWorkflow(file))
      .filter((step) => NEON_DIST.test(step.run))
      .map((step) => ({ file, ...step })),
  )

  it('is invoked somewhere, or this guard is checking nothing', () => {
    expect(calls.length).toBeGreaterThan(0)
  })

  it.each(calls)('$file › $jobId › $name passes the crate name', ({ run }) => {
    // Line continuations first: the flag and its value are allowed to be split
    // across lines, and without this the pattern below would not see them.
    const flat = run.replace(/\\\n\s*/g, ' ')
    const named = flat.match(/(?:^|\s)(?:-n|--name)\s+(\S+)/)
    expect(
      named,
      'neon dist needs -n; $npm_package_name is unset under pnpm exec',
    ).not.toBeNull()
    expect(named[1]).toBe(crateName())
  })
})
