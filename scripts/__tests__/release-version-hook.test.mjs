import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The EQL release ships five artifacts at ONE version V: the `@cipherstash/eql`
 * npm package, the `eql-bindings` crate, the SQL install/uninstall bundle, the
 * API docs, and the `postgres-eql` image. Changesets computes V from the npm
 * package alone; `scripts/sync-lockstep-versions.mjs` is what carries it to the
 * other four, by writing `[package] version` into the crate's `Cargo.toml` and
 * rebuilding the bundled SQL assets at that exact version.
 *
 * That script runs as the second half of the root `version` script — and
 * `changesets/action` only invokes it if the step passes `version:`. Omit that
 * one input and the action silently runs its OWN built-in `changeset version`
 * instead. Nothing errors. npm bumps to V, `Cargo.toml` stays at V-1, and the
 * bundled SQL keeps the version it was generated against, so release-plz
 * publishes a crate whose version disagrees with the SQL it ships. The first
 * person to notice is a user whose installed bundle does not match the crate
 * they depend on.
 *
 * This is the seam the protect-ffi round warned about in the abstract: a
 * pass-through input whose absence is indistinguishable from success. It fails
 * open, it fails silently, and it fails at the only moment that is expensive to
 * undo — after a publish. Hence a test rather than a comment.
 *
 * The three assertions are deliberately separate: that the workflow asks for a
 * version step at all, that it routes through the ROOT script (not a bare
 * `changeset version`, which would version npm and skip the propagation), and
 * that the root script actually chains the propagation on. Any one of the three
 * alone still permits the silent-skew failure.
 */

const RELEASE_WORKFLOW = '.github/workflows/release.yml'
const CHANGESETS_ACTION = 'changesets/action'
const VERSION_SCRIPT = 'sync-lockstep-versions.mjs'

/** Every step in a workflow, flattened across jobs, with its job name. */
function steps(workflow) {
  return Object.entries(workflow.jobs ?? {}).flatMap(([jobName, job]) =>
    (job.steps ?? []).map((step) => ({ jobName, step })),
  )
}

describe('release.yml drives the lockstep version hook', () => {
  const workflow = readWorkflow(RELEASE_WORKFLOW)
  const changesetSteps = steps(workflow).filter(({ step }) =>
    (step.uses ?? '').startsWith(CHANGESETS_ACTION),
  )

  it('uses changesets/action at all', () => {
    // Guards the guard: if the release ever stops going through this action,
    // the assertions below would pass vacuously over an empty list.
    expect(changesetSteps.length).toBeGreaterThan(0)
  })

  it('passes a `version:` input to every changesets/action step', () => {
    for (const { jobName, step } of changesetSteps) {
      expect(
        step.with?.version,
        `${RELEASE_WORKFLOW} job '${jobName}': changesets/action has no \`version:\` input, so it ` +
          'runs its built-in `changeset version` and never invokes the root `version` script. ' +
          'npm would bump while the crate and bundled SQL keep the old version.',
      ).toBeTruthy()
    }
  })

  it('routes `version:` through the root script, not a bare `changeset version`', () => {
    for (const { jobName, step } of changesetSteps) {
      expect(
        step.with?.version,
        `${RELEASE_WORKFLOW} job '${jobName}': \`version:\` must run the root \`version\` script ` +
          '(`pnpm run version`). Calling `changeset version` directly versions npm and skips the ' +
          'lockstep propagation to the crate and SQL bundle.',
      ).toMatch(/\brun version\b/)
    }
  })
})

describe('the root `version` script chains the propagation', () => {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'))

  it('exists', () => {
    expect(
      pkg.scripts?.version,
      'root package.json has no `version` script, so `version: pnpm run version` in release.yml ' +
        "would fail — or worse, resolve to npm's own lifecycle behaviour.",
    ).toBeTruthy()
  })

  it('runs `changeset version` AND the lockstep sync, in that order', () => {
    const script = pkg.scripts.version
    expect(script).toContain('changeset version')
    expect(
      script,
      `root \`version\` script does not invoke ${VERSION_SCRIPT}, so the computed version would ` +
        'reach npm and nothing else.',
    ).toContain(VERSION_SCRIPT)
    expect(
      script.indexOf('changeset version'),
      'the lockstep sync reads the version changesets just wrote, so it must run second.',
    ).toBeLessThan(script.indexOf(VERSION_SCRIPT))
  })
})

/**
 * The same hook, reached the way a human reaches it.
 *
 * `release.yml` is not the only caller. `AGENTS.md` documents the release flow
 * as `pnpm changeset:version`, and that alias was a bare `changeset version` —
 * so a maintainer following this repo's own documentation reproduced exactly
 * the skew the hook exists to prevent: npm bumped, the crate and the bundled
 * SQL left behind. The workflow test above passes throughout, because the
 * workflow is not what ran.
 *
 * The rule is stated over the SCRIPTS rather than over the one name, so a
 * second convenience alias added later is held to it without anyone
 * remembering this file exists. Two changeset commands are wrapped by this
 * repo, and both wrappers are load-bearing:
 *
 *   * `changeset version` must chain `sync-lockstep-versions.mjs`, or the
 *     lockstep bump reaches npm and nothing else.
 *   * `changeset publish` must build first, or it packs whatever `dist/` the
 *     working tree happens to hold — which for a clean clone is nothing.
 *
 * A script that wraps neither (`pnpm run version`, `pnpm run release`) is not
 * matched and needs no exemption: it does not contain the bare command.
 */
describe('no root script invokes a bare changesets command', () => {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'))
  const scripts = Object.entries(pkg.scripts ?? {})

  /** Scripts whose body runs `changeset <command>`, other than via `pnpm run`. */
  const invoking = (command) =>
    scripts.filter(([, body]) =>
      new RegExp(`(^|[\\s;&|(])changeset\\s+${command}\\b`).test(body),
    )

  it('finds the wrappers it is checking', () => {
    // The floor. Both rules below are "for every script that runs X…", and a
    // repo where nothing matches passes them having checked nothing — which is
    // also what a rename of the changesets CLI would produce.
    expect(invoking('version').length).toBeGreaterThan(0)
    expect(invoking('publish').length).toBeGreaterThan(0)
  })

  it('chains the lockstep sync onto every `changeset version`', () => {
    const offenders = invoking('version')
      .filter(([, body]) => !body.includes(VERSION_SCRIPT))
      .map(([name, body]) => `${name}: ${body}`)
    expect(
      offenders,
      `A root script runs \`changeset version\` without ${VERSION_SCRIPT}. It bumps the npm ` +
        'package and leaves packages/eql/crates/eql-bindings/Cargo.toml, every Cargo.lock that ' +
        'records it, and the bundled SQL at the previous version. Route the alias through ' +
        '`pnpm run version` instead of calling the changesets CLI directly.',
    ).toEqual([])
  })

  it('builds before every `changeset publish`', () => {
    const offenders = invoking('publish')
      .filter(([, body]) => !/\brun build\b/.test(body))
      .map(([name, body]) => `${name}: ${body}`)
    expect(
      offenders,
      'A root script runs `changeset publish` without building first, so it packs whatever ' +
        '`dist/` the working tree happens to hold. Route the alias through `pnpm run release`.',
    ).toEqual([])
  })
})
