import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * Every `scripts/` entry point must decide "was I run directly?" the same way,
 * and the two available ways are not equivalent.
 *
 * The fragile form compares a URL against a path:
 *
 *     if (import.meta.url === `file://${process.argv[1]}`)
 *
 * `import.meta.url` is percent-encoded; `process.argv[1]` is not. On any
 * checkout path containing a space — or any other character a file URL encodes
 * — the two strings differ, the guard is false, `main()` never runs, and the
 * script exits 0 having done nothing. The robust form decodes the URL back to
 * a path before comparing:
 *
 *     if (process.argv[1] === fileURLToPath(import.meta.url)) main()
 *
 * The failure mode is why this guard is repo-wide rather than a comment on the
 * one file that got it wrong. A silent exit 0 is indistinguishable from
 * success to every caller: `package.json`'s `version` script is
 * `changeset version && node scripts/sync-lockstep-versions.mjs`, and the `&&`
 * means the no-op reports success while `changeset version` has already bumped
 * the npm package — producing exactly the lockstep skew that script exists to
 * prevent. CI never sees it (`/home/runner/work/stack/stack` has no space), so
 * nothing but this test stands between the outlier and a release.
 */

/** Absolute paths of every `scripts/*.mjs` that is not a test or config file. */
function scriptFiles() {
  const dir = join(REPO_ROOT, 'scripts')
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.mjs'))
    .filter((e) => e.name !== 'vitest.config.mjs')
    .map((e) => join(dir, e.name))
    .sort()
}

/** Source with runs of whitespace flattened, so formatting cannot hide a form. */
function flatten(path) {
  return readFileSync(path, 'utf8').replace(/\s+/g, ' ')
}

/** `true` when the file decides whether it is the entry point. */
function hasMainGuard(src) {
  return src.includes('process.argv[1]') && src.includes('import.meta.url')
}

const ROBUST =
  /(process\.argv\[1\] === fileURLToPath\(import\.meta\.url\)|fileURLToPath\(import\.meta\.url\) === process\.argv\[1\])/

/** The percent-encoding-blind comparison, in either operand order. */
const FRAGILE =
  /(import\.meta\.url === `file:\/\/|`file:\/\/\$\{[^`]*` === import\.meta\.url)/

describe('scripts/ main-guards survive a checkout path with a space', () => {
  test('the scan finds the entry points it is meant to police', () => {
    // Without this the suite goes vacuous the moment the directory layout
    // moves: an empty file list passes every assertion below.
    const guarded = scriptFiles().filter((p) => hasMainGuard(flatten(p)))
    expect(guarded.length).toBeGreaterThanOrEqual(4)
  })

  test('every main-guard uses fileURLToPath, never a `file://` template', () => {
    const offenders = []
    for (const path of scriptFiles()) {
      const src = flatten(path)
      if (!hasMainGuard(src)) continue
      if (FRAGILE.test(src) || !ROBUST.test(src)) {
        offenders.push(path.slice(REPO_ROOT.length + 1))
      }
    }

    expect(
      offenders,
      'these scripts compare `import.meta.url` to an unencoded path, so they ' +
        'silently exit 0 without running `main()` from any checkout path ' +
        'containing a space. Use ' +
        '`if (process.argv[1] === fileURLToPath(import.meta.url)) main()`.',
    ).toEqual([])
  })
})
