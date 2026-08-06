import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-dead-package-paths.mjs',
)

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

  // The whole reason `livePackages` comes from git rather than from
  // `readdirSync`, pinned in the discriminating direction (#772 review,
  // finding 15).
  //
  // Deleting a package leaves its gitignored `dist/` and `node_modules/`
  // behind, so the directory is still on disk and any filesystem-derived live
  // set calls it live — silently excusing every reference to it. The test
  // above, `treats a package that exists but is not yet tracked as live`, does
  // NOT pin this: it builds a divergence that `readdirSync` and git agree on,
  // so it passes under a revert. This one is the only test that fails under
  // both a plain `readdirSync` revert and the more plausible
  // `readdirSync`-unioned-with-git hybrid.
  //
  // The shell's contents MUST be gitignored. If they aren't, the
  // `--others --exclude-standard` arm legitimately counts the package as live
  // and this test would assert the opposite of what it claims — so guard on a
  // clean `git status` and fail loudly rather than silently degrading.
  it('flags a deleted package whose gitignored dist/ shell survives on disk', () => {
    const shell = resolve(REPO_ROOT, 'packages/lint-dead-shell-probe')
    try {
      mkdirSync(resolve(shell, 'dist'), { recursive: true })
      writeFileSync(resolve(shell, 'dist/index.js'), 'exports.x = 1\n')
      mkdirSync(resolve(shell, 'node_modules'), { recursive: true })
      writeFileSync(resolve(shell, 'node_modules/.keep'), '')

      // Scoped to the probe alone: asserting the whole `packages/` tree is
      // clean would couple this to whatever else is uncommitted in the
      // working copy, which is nobody's business but the developer's.
      const visible = execFileSync(
        'git',
        ['status', '--porcelain', 'packages/lint-dead-shell-probe'],
        { cwd: REPO_ROOT, encoding: 'utf8' },
      )
      expect(visible).toBe('')

      const r = run(fx('dead-shell.md'))
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/packages\/lint-dead-shell-probe/)
    } finally {
      rmSync(shell, { recursive: true, force: true })
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

  // A linter whose whole job is catching dead paths in configuration silently
  // ignored dead paths in its OWN configuration: a target that did not exist
  // was skipped, so a renamed or moved entry dropped out of coverage forever
  // with a green build. Its sibling `lint-no-hardcoded-runners.mjs` exits 2 on
  // a stale allowlist entry — same rot, opposite handling, same PR.
  //
  // Exit 2, not 1: the linter could not check what it was asked to check,
  // which is not the same as "your docs are wrong".
  it('exits 2 when a target does not exist rather than skipping it', () => {
    const r = run(fx('no-such-fixture.md'))
    expect(r.exitCode).toBe(2)
    expect(r.output).toMatch(/no-such-fixture\.md/)
    expect(r.output).not.toMatch(/at ModuleJob/)
  })

  // `relative(REPO_ROOT, file)` renders a target outside the repo as a
  // `../../../../..` chain climbing out of the root — technically resolvable,
  // unreadable in practice, and it buries the one thing the line is for.
  // Unreachable via the default target list, which is repo-relative
  // throughout; reachable the moment anyone passes an argv override.
  it('renders an absolute path for an offender outside the repo root', () => {
    const dir = mkdtempSync(join(tmpdir(), 'lint-dead-package-paths-'))
    try {
      const file = join(dir, 'outside.md')
      writeFileSync(file, 'Points at packages/lint-dead-shell-probe, gone.\n')
      const r = run(file)
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/packages\/lint-dead-shell-probe/)
      expect(r.output).toContain(file)
      expect(r.output).not.toMatch(/\.\.\//)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
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
