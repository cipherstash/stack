import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-dead-package-paths.mjs',
)

function run(...targets) {
  try {
    execFileSync('node', [SCRIPT, ...targets], { encoding: 'utf8' })
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
  // so a `packages/drizzle` allowlist entry for a package that never existed in
  // git history sat there unnoticed. Its own fixtures must stay exempt.
  it('scans scripts/ but not its fixtures', () => {
    const r = run()
    expect(r.exitCode).toBe(0)
    expect(r.output).toBe('')
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
