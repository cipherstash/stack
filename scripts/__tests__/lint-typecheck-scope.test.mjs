import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-typecheck-scope.mjs',
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

const fx = (name) => `scripts/__tests__/fixtures/lint-typecheck-scope/${name}`

describe('lint-typecheck-scope', () => {
  it('passes on the repo as it stands', () => {
    const r = run()
    expect(r.output).toBe('')
    expect(r.exitCode).toBe(0)
  })

  it('fails a gated package whose tsconfig scopes nothing', () => {
    const r = run(fx('unscoped'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/@fixture\/unscoped/)
    expect(r.output).toMatch(/compiles its own build output/)
  })

  it('names the offending tsconfig and the gate command', () => {
    const r = run(fx('unscoped'))
    expect(r.output).toMatch(/unscoped\/tsconfig\.json/)
    expect(r.output).toMatch(/tsc --noEmit -p tsconfig\.json/)
  })

  it('passes when `exclude` covers dist', () => {
    expect(run(fx('excludes-dist')).exitCode).toBe(0)
  })

  it('passes when an explicit `include` scopes the program', () => {
    expect(run(fx('has-include')).exitCode).toBe(0)
  })

  it('ignores a package with no typecheck gate', () => {
    // An unscoped tsconfig nothing runs is an editor setting, not a CI
    // contract — flagging it would be noise.
    expect(run(fx('no-gate')).exitCode).toBe(0)
  })

  it('parses a tsconfig with comments, block comments and a `/*` inside a path key', () => {
    // Regression: the first cut stripped block comments with a regex, which ate
    // from the `/*` inside the `"@/*"` mapping key to the next comment close and
    // reported four real tsconfigs as unparseable.
    const r = run(fx('jsonc-paths'))
    expect(r.output).not.toMatch(/could not be parsed/)
    expect(r.exitCode).toBe(0)
  })

  it('counts only the offenders among the targets it was given', () => {
    const r = run(fx('unscoped'), fx('no-gate'), fx('excludes-dist'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/Found 1 typecheck gate\(s\)/)
  })

  it('reports every offender, not just the first', () => {
    const r = run(fx('unscoped'), fx('unscoped-too'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/Found 2 typecheck gate\(s\)/)
    expect(r.output).toMatch(/@fixture\/unscoped\b/)
    expect(r.output).toMatch(/@fixture\/unscoped-too/)
  })

  it('explains the fix, including that `exclude` replaces the default', () => {
    const r = run(fx('unscoped'))
    expect(r.output).toMatch(/"exclude": \["dist", "node_modules"\]/)
    expect(r.output).toMatch(/REPLACES the default/)
  })
})
