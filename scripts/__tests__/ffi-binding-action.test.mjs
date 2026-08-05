/**
 * Guards the two supply-chain-shaped properties of the protect-ffi build
 * action and the Rust workflow that shares its toolchain step.
 *
 * 1. A GitHub Actions cache restore is an untrusted write into the checkout.
 *    `packages/protect-ffi/dist/wasm` holds BOTH wasm-pack output and three
 *    declaration files that are tracked in git (see the package `.gitignore`
 *    for why they are tracked). Caching that directory whole, on a key hashed
 *    from the Rust inputs only, means a restore replaces the checked-out
 *    declarations with whatever a previous run happened to archive — silently,
 *    and with no diff to show for it. Either the key has to move when those
 *    files move, or they must not be in the archive at all.
 *
 * 2. `jdx/mise-action` is a third-party action this repo did not depend on
 *    before the absorption, and it runs in jobs that hold live CipherStash
 *    credentials. A mutable major tag means the code that runs there can change
 *    without a commit here. SHA-pin it, per the convention the deposited
 *    upstream workflows already use.
 *
 * The scan-found-something assertions are not padding. Both properties are
 * expressed as "nothing in this set violates X", and an empty set satisfies
 * that for free — the same failure mode `lintWiring.test.ts` and
 * `scripts/lint-no-hardcoded-runners.mjs` exist to rule out.
 */
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

const ACTION = '.github/actions/build-ffi-binding/action.yml'
const RUST_WORKFLOW = '.github/workflows/tests-rust.yml'

const read = (rel) => readFileSync(resolve(REPO_ROOT, rel), 'utf8')

/**
 * Files git tracks under a workspace-relative path or pathspec.
 *
 * Derived at test time rather than hardcoded: a fourth tracked declaration
 * file added to `dist/wasm` must fail this suite, not slip past a stale list.
 */
function trackedUnder(pathspec) {
  const stdout = execFileSync('git', ['ls-files', '-z', '--', pathspec], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
  })
  return stdout.split('\0').filter(Boolean)
}

/**
 * Approximates the `@actions/glob` semantics that both `actions/cache`'s
 * `path:` and `hashFiles()` are built on: `*` stops at a path separator, `**`
 * does not, and a pattern that names a directory implicitly covers everything
 * beneath it (`implicitDescendants`, on by default in both).
 */
function globToRegExp(pattern) {
  let source = '^'
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        source += '.*'
        i += 1
        if (pattern[i + 1] === '/') i += 1
      } else {
        source += '[^/]*'
      }
    } else if (ch === '?') {
      source += '[^/]'
    } else {
      source += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    }
  }
  // The implicit-descendants tail. Harmless on a pattern that names a file.
  return new RegExp(`${source}(?:/.*)?$`)
}

const globMatches = (pattern, path) => globToRegExp(pattern).test(path)

/** Splits a cache `path:` block into include and exclude (`!`) patterns. */
function splitCachePaths(value) {
  const lines = String(value ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
  return {
    includes: lines.filter((line) => !line.startsWith('!')),
    excludes: lines
      .filter((line) => line.startsWith('!'))
      .map((line) => line.slice(1).trim()),
  }
}

const isGlob = (pattern) => /[*?[]/.test(pattern)

/**
 * Every git-tracked file that would end up inside the step's cache archive.
 *
 * The `!` handling here is deliberately narrow, because `actions/cache`'s is.
 * It resolves `path:` through `@actions/glob` with `implicitDescendants: false`
 * and feeds the result to `tar --files-from`, which recurses on its own. So an
 * include naming a DIRECTORY yields exactly that one path, tar walks the whole
 * subtree, and a `!` pattern aimed at files underneath never fires — those
 * files were never glob results to subtract from. Excludes only bite when the
 * include enumerates files.
 */
function trackedFilesInArchive(step) {
  const { includes, excludes } = splitCachePaths(step?.with?.path)
  const archived = new Set()
  for (const include of includes) {
    const dir = include.replace(/\/$/, '')
    for (const file of trackedUnder(include)) {
      if (!isGlob(include) && file.startsWith(`${dir}/`)) {
        archived.add(file) // swept up by tar's recursion; excludes cannot help
      } else if (!excludes.some((pattern) => globMatches(pattern, file))) {
        archived.add(file)
      }
    }
  }
  return [...archived]
}

/** The glob arguments of every `hashFiles(...)` call in a cache key. */
function hashFilesPatterns(key) {
  const patterns = []
  for (const call of String(key ?? '').matchAll(/hashFiles\(([^)]*)\)/g)) {
    for (const arg of call[1].matchAll(/'([^']*)'/g)) patterns.push(arg[1])
  }
  return patterns
}

const CACHE_ACTION = /^actions\/cache(\/(restore|save))?@/

const actionDoc = yaml.load(read(ACTION))
const actionSteps = actionDoc?.runs?.steps ?? []
const cacheSteps = actionSteps.filter(
  (step) => typeof step?.uses === 'string' && CACHE_ACTION.test(step.uses),
)
const label = (step, idx) => step?.name ?? step?.uses ?? `step #${idx + 1}`

describe('build-ffi-binding — cache restores cannot clobber tracked files', () => {
  it('found the cache steps it means to check', () => {
    // Two today: index.node and dist/wasm. If this drops to zero the property
    // below becomes a tautology over an empty list.
    expect(cacheSteps.length).toBeGreaterThanOrEqual(2)
    for (const [idx, step] of cacheSteps.entries()) {
      expect(step?.with?.path, `${label(step, idx)} has no path`).toBeTruthy()
      expect(step?.with?.key, `${label(step, idx)} has no key`).toBeTruthy()
    }
  })

  it('found the tracked declaration files this guard exists for', () => {
    // If `git ls-files` returns nothing here — wrong cwd, renamed directory,
    // the .gitignore negations lost — every assertion below passes vacuously.
    const tracked = trackedUnder('packages/protect-ffi/dist/wasm')
    expect(tracked.length).toBeGreaterThanOrEqual(3)
    expect(tracked.every((file) => file.endsWith('.d.ts'))).toBe(true)
  })

  for (const [idx, step] of cacheSteps.entries()) {
    const name = label(step, idx)
    it(`"${name}" archives no tracked file its key does not cover`, () => {
      const uncovered = trackedFilesInArchive(step).filter(
        (file) =>
          !hashFilesPatterns(step?.with?.key).some((pattern) =>
            globMatches(pattern, file),
          ),
      )
      // Either shape is sound: exclude the tracked files from the archive so a
      // restore cannot reach them, or hash them into the key so any restore
      // that lands necessarily carries identical content. Both are fine; a
      // tracked file that is in the archive AND absent from the key is not.
      expect(uncovered).toEqual([])
    })
  }
})

describe('jdx/mise-action is pinned to an immutable commit', () => {
  const files = [ACTION, RUST_WORKFLOW]

  for (const file of files) {
    const refs = [...read(file).matchAll(/jdx\/mise-action@(\S+)/g)].map(
      (m) => m[1],
    )

    it(`${file} references mise-action at all`, () => {
      // The pin assertion is "every ref is a SHA"; zero refs satisfies it.
      expect(refs.length).toBeGreaterThanOrEqual(1)
    })

    it(`${file} pins mise-action by SHA, not by tag`, () => {
      for (const ref of refs) expect(ref).toMatch(/^[0-9a-f]{40}$/)
    })

    it(`${file} annotates each mise-action pin with its tag`, () => {
      // `@<sha> # <tag>` is the convention the deposited upstream workflows
      // use. The comment is what keeps the pin readable and lets Dependabot
      // rewrite both halves together.
      const lines = read(file)
        .split('\n')
        .filter((line) => line.includes('jdx/mise-action@'))
      expect(lines.length).toBe(refs.length)
      for (const line of lines) expect(line).toMatch(/#\s*v\d/)
    })
  }
})

describe('build-ffi-binding — composite action shape', () => {
  it('parses and declares steps', () => {
    expect(actionDoc?.runs?.using).toBe('composite')
    expect(actionSteps.length).toBeGreaterThan(0)
  })

  it('gives every `run:` step a `shell:`', () => {
    // A composite action has no default shell; omitting it fails the whole
    // workflow at load time with "Required property is missing: shell".
    const missing = actionSteps
      .map((step, idx) => (step?.run && !step?.shell ? label(step, idx) : null))
      .filter(Boolean)
    expect(missing).toEqual([])
  })
})
