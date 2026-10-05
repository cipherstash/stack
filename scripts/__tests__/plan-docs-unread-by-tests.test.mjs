import { execFileSync } from 'node:child_process'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * `tests.yml` skips pull requests that change only `docs/plans/`, which is
 * safe only while no test reads a plan. A test that did would go red on
 * `main` after a plan edit merged with no checks.
 *
 * This reads text, so it sees a plan path written out, not one built at run
 * time.
 */

const TESTS = [':(glob)**/__tests__/**', ':(glob)**/*.test.*', ':(glob)e2e/**']

function filesNamingAPlan(pathspecs) {
  try {
    return execFileSync(
      'git',
      [
        'grep',
        '-l',
        '-E',
        'docs/plans/[A-Za-z0-9_.-]+\\.md',
        '--',
        ...pathspecs,
      ],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
      .split('\n')
      .filter(Boolean)
  } catch (error) {
    // git grep exits 1 when nothing matches.
    if (error.status === 1) return []
    throw error
  }
}

describe('tests.yml skips pull requests that change only docs/plans/', () => {
  it('no test names a file under docs/plans/', () => {
    expect(
      filesNamingAPlan(TESTS),
      'A test that reads a plan is skipped on a plan-only pull request, because `tests.yml` ignores `docs/plans/**`. Move the fact the test needs out of the plan, or drop the negation from the `pull_request` filter.',
    ).toEqual([])
  })
  it('the scan finds a plan name when there is one', () => {
    expect(filesNamingAPlan(['scripts/release-gate.mjs'])).toEqual([
      'scripts/release-gate.mjs',
    ])
  })
})
