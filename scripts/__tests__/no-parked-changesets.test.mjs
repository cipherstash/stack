import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * The `.changeset/*.md.deferred` parking convention is RETIRED, and nothing
 * else notices a file left behind under it.
 *
 * ## What the convention was
 *
 * Until the phase-4 publishing cutover, npm trusted publishing for the seven
 * `@cipherstash/protect-ffi` packages named `cipherstash/protectjs-ffi`. A
 * changeset naming any of them would bump all seven (they share a fixed group)
 * and the next release would attempt a publish this repository was not
 * authorised to make. `scripts/lint-no-ffi-changeset.mjs` failed CI on one, and
 * the escape hatch was to write the changeset under `.md.deferred` — a suffix
 * `@changesets/read` does not select — so the cutover PR could `git mv` it back
 * rather than reconstruct the prose from a git log months later.
 *
 * ## Why a leftover is worse than the hazard it replaced
 *
 * The cutover has happened. The guard, its self-test and its fixtures are gone,
 * and publishing for all seven is bound to this repository's `release.yml`. So
 * the suffix no longer defers anything — it just hides. `changeset version`
 * does not read the file, `changeset publish` does not warn about it, and the
 * package ships with an empty changelog entry for a user-visible change.
 *
 * That is the precise failure mode this repository keeps rediscovering in other
 * forms: a check that arrives as a file and executes on no event reads exactly
 * like a check that passes. AGENTS.md states the rule in prose — "If you find
 * such a file, `git mv` it back to `.md`, or the change it describes ships with
 * no changelog entry. Nothing detects one for you." This is the "nothing".
 *
 * ## The case that motivated it, which is the less obvious one
 *
 * The cutover itself did this correctly: `e77bfcec` retired the guard AND
 * renamed both parked files in the same commit, and `@cipherstash/protect-ffi`
 * released at 0.32.0 with their contents in its CHANGELOG.
 *
 * The hazard is the LONG-LIVED BRANCH cut before that commit. It carries the
 * files under the old suffix, where they are invisible to every tool, and they
 * survive a merge with the cutover — the branch side has a path the base side
 * deleted. Reactivating them there is worse than leaving them: it re-publishes
 * a changelog entry that has already shipped and bumps the package for a change
 * released two versions ago. Deleting them is the fix on that side, and this
 * test accepts either resolution because it asserts the SUFFIX is absent, not
 * which way it went.
 *
 * So the message below names both routes, and the branch-side one first: by the
 * time anyone sees this failure the cutover is behind them, and "rename it
 * back" is the answer that is usually wrong.
 *
 * ## Why it also asserts the guard is gone
 *
 * A half-retired convention is the state that produces a parked file. If
 * `lint:ffi-changeset` were reinstated while this test stood, the two would
 * contradict each other and whichever ran second would decide — so the retirement
 * is asserted as one fact, not three independent ones.
 */

const CHANGESET_DIR = '.changeset'

/** The suffix the retired convention used to park a changeset under. */
const PARKED_SUFFIX = '.md.deferred'

/** The guard that enforced the convention, deleted by the cutover. */
const RETIRED_GUARD = 'scripts/lint-no-ffi-changeset.mjs'

/** The root `package.json` script that invoked it. */
const RETIRED_SCRIPT = 'lint:ffi-changeset'

describe('the changeset parking convention is retired, and stays retired', () => {
  const entries = readdirSync(join(REPO_ROOT, CHANGESET_DIR))

  // The guard on the scan: a discovery test reading an empty directory passes
  // while checking nothing. `.changeset/` always holds at least README.md and
  // config.json, so this cannot be satisfied by a bad path.
  it('reads the changeset directory it means to check', () => {
    expect(entries).toContain('config.json')
    expect(entries).toContain('README.md')
  })

  it('has no parked changeset left behind', () => {
    const parked = entries.filter((name) => name.endsWith(PARKED_SUFFIX))

    expect(
      parked,
      `These changesets are parked under the retired \`${PARKED_SUFFIX}\` convention. ` +
        '`@changesets/read` does not select that suffix, so each one describes a change ' +
        'that will release with an empty changelog entry — silently, because nothing in ' +
        '`changeset version` or `changeset publish` reports a file it did not read.\n\n' +
        'CHECK WHICH CASE THIS IS BEFORE RENAMING. The cutover (`e77bfcec`) already ' +
        'renamed the files that were parked at the time, and they released in ' +
        '`@cipherstash/protect-ffi@0.32.0`. A file still carrying the suffix today is ' +
        'almost certainly riding a branch cut BEFORE that commit, where reactivating it ' +
        'republishes a shipped changelog entry and bumps the package again for it:\n\n' +
        '  git log origin/main --oneline -- packages/protect-ffi/CHANGELOG.md\n\n' +
        'Delete it if its content is already in a released CHANGELOG; `git mv` it back to ' +
        '`.md` only if it is genuinely unreleased:\n' +
        `${parked.map((name) => `  ${CHANGESET_DIR}/${name}`).join('\n')}`,
    ).toEqual([])
  })

  it('no longer carries the guard that required parking', () => {
    expect(
      existsSync(join(REPO_ROOT, RETIRED_GUARD)),
      `${RETIRED_GUARD} enforced the parking convention this file retires. With both ` +
        'present, a changeset naming a protect-ffi package fails CI while the test above ' +
        'forbids the only workaround — so the two guards contradict each other and the ' +
        'change has nowhere to go. Delete one; the cutover deleted this one.',
    ).toBe(false)
  })

  it('no root script invokes the retired guard', () => {
    const scripts =
      JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'))
        .scripts ?? {}

    expect(
      Object.keys(scripts),
      `The root \`${RETIRED_SCRIPT}\` script runs a guard the cutover deleted. Left in ` +
        'place it fails with a module-not-found error rather than a lint message, which ' +
        'reads as a broken toolchain.',
    ).not.toContain(RETIRED_SCRIPT)
  })

  it('no workflow step invokes the retired guard', () => {
    const offenders = workflowFiles().flatMap((relPath) => {
      const workflow = readWorkflow(relPath)
      return Object.entries(workflow?.jobs ?? {}).flatMap(([jobName, job]) =>
        (job?.steps ?? [])
          .filter((step) => (step?.run ?? '').includes(RETIRED_SCRIPT))
          .map(() => `${relPath} → ${jobName}`),
      )
    })

    expect(
      offenders,
      `These jobs still run \`pnpm run ${RETIRED_SCRIPT}\`, whose script the cutover ` +
        `deleted. The step fails every run — and it fails AFTER the checkout and install, ` +
        'so the cost is a full job rather than a fast one.\n' +
        `${offenders.map((line) => `  ${line}`).join('\n')}`,
    ).toEqual([])
  })
})
