import { execFileSync } from 'node:child_process'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-dead-package-paths.mjs',
)

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

function run(...targets) {
  return runWith({}, ...targets)
}

function runWith(opts, ...targets) {
  try {
    execFileSync(process.execPath, [SCRIPT, ...targets], {
      encoding: 'utf8',
      ...opts,
    })
    return { exitCode: 0, output: '' }
  } catch (err) {
    return {
      exitCode: err.status,
      output: String(err.stdout) + String(err.stderr),
    }
  }
}

const fx = (name) =>
  resolve(
    fileURLToPath(import.meta.url),
    `../fixtures/lint-no-dead-package-paths/${name}`,
  )

describe('lint-no-dead-package-paths', () => {
  it('passes on the repo as it stands', () => {
    const r = run()
    expect(r.output).toBe('')
    expect(r.exitCode).toBe(0)
  })

  it('passes when every `packages/<name>` reference resolves', () => {
    expect(run(fx('live-refs.md')).exitCode).toBe(0)
  })

  it('fails on a reference to a deleted package', () => {
    const r = run(fx('dead-ref.md'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/packages\/protect/)
  })

  // #772 review, finding 15. The name capture had no right anchor, so a
  // sentence-final `packages/stack.` swallowed the period and the linter
  // reported a LIVE package as dead — failing the build with a message naming a
  // directory that plainly exists. Never fired in 400 commits only because the
  // repo's backtick convention happened to dodge it.
  it('does not flag a live package followed by sentence punctuation', () => {
    const r = run(fx('sentence-final.md'))
    expect(r.output).toBe('')
    expect(r.exitCode).toBe(0)
  })

  // The character class excluded uppercase, so `packages/Foo` was never checked
  // at all — a silent hole rather than a false alarm.
  it('checks a package name containing uppercase', () => {
    const r = run(fx('uppercase.md'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/packages\/Foo/)
  })

  // The linters carry package paths of their own; `scripts/` was not scanned,
  // so lint-no-hardcoded-runners' `packages/drizzle/src/bin/runner.ts` allowlist
  // entry — added speculatively by c6715608, load-bearing 31 minutes later once
  // 9d259e6e created the file — sat dead for the two months after 413ca396
  // deleted the package. Its sibling entry for `packages/protect` was removed
  // with its package; this one was simply missed.
  //
  // Asserting the repo is clean would NOT pin this: the suite's first test
  // already does that, and both pass whether or not `scripts` is in TARGETS.
  // Plant an offender in the scanned directory instead.
  it('scans scripts/ but not its fixtures', () => {
    const probe = resolve(REPO_ROOT, 'scripts/dead-path-probe.md')
    try {
      writeFileSync(probe, 'A reference to `packages/protect`, long gone.\n')
      const r = run()
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/scripts\/dead-path-probe\.md:1/)
      // `__tests__` stays skipped — the fixtures name dead packages on purpose,
      // and so do the comments in this very file.
      expect(r.output).not.toMatch(/__tests__/)
    } finally {
      rmSync(probe, { force: true })
    }
  })

  // A package scaffolded a minute ago is live, but nothing about it is tracked
  // yet. Deriving the live set from `git ls-files` alone reported it as "does
  // not exist" — the same species of false alarm as the sentence-final one
  // above, pointed the other way, at a directory sitting right there on disk.
  it('treats a package that exists but is not yet tracked as live', () => {
    const pkg = resolve(REPO_ROOT, 'packages/lint-untracked-probe')
    try {
      mkdirSync(resolve(pkg, 'src'), { recursive: true })
      writeFileSync(resolve(pkg, 'src/index.ts'), 'export const x = 1\n')
      const r = run(fx('untracked-package.md'))
      expect(r.output).toBe('')
      expect(r.exitCode).toBe(0)
    } finally {
      rmSync(pkg, { recursive: true, force: true })
    }
  })

  // The live set is derived by shelling out to git, so git failing is a mode
  // this linter has to own. Exiting 1 with a raw ENOENT stack trace would be
  // indistinguishable from a genuine lint failure; exit 2 says "the linter
  // could not run", not "your docs are wrong".
  it('exits 2 with an actionable message when git is unavailable', () => {
    const r = runWith({
      env: { PATH: resolve(REPO_ROOT, 'scripts/nonexistent') },
    })
    expect(r.exitCode).toBe(2)
    expect(r.output).toMatch(/git/)
    expect(r.output).toMatch(/checkout/)
    expect(r.output).not.toMatch(/at ModuleJob/)
  })

  it('names the file and line of each offender', () => {
    const r = run(fx('dead-ref.md'))
    expect(r.output).toMatch(/dead-ref\.md:3/)
  })

  it('reports every offender, not just the first', () => {
    const r = run(fx('many-dead-refs.md'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/packages\/protect\b/)
    expect(r.output).toMatch(/packages\/schema\b/)
    expect(r.output).toMatch(/packages\/protect-dynamodb\b/)
  })

  it('flags dead paths in YAML comments too', () => {
    const r = run(fx('dead-ref.yml'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/packages\/protect/)
  })

  it('matches the longest package name, not a shorter prefix', () => {
    // `packages/stack-drizzle` must not be read as `packages/stack` + suffix,
    // and a dead `packages/stack-forge` must not be excused by live
    // `packages/stack`.
    const r = run(fx('prefix.md'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/packages\/stack-forge/)
    expect(r.output).not.toMatch(/packages\/stack-drizzle/)
  })

  it('ignores `packages/*` globs and `./packages/*` filters', () => {
    expect(run(fx('globs.md')).exitCode).toBe(0)
  })

  it('walks a directory target', () => {
    const r = run(fx('dir'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/nested\.md/)
  })

  it('skips CHANGELOG.md — released history names deleted packages', () => {
    expect(run(fx('dir-with-changelog')).exitCode).toBe(0)
  })
})
