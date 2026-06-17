import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-hardcoded-runners.mjs',
)

function run(target) {
  try {
    execFileSync('node', [SCRIPT, target], { encoding: 'utf8' })
    return { exitCode: 0, output: '' }
  } catch (err) {
    return {
      exitCode: err.status,
      output: String(err.stdout) + String(err.stderr),
    }
  }
}

describe('lint-no-hardcoded-runners', () => {
  const fx = (name) =>
    resolve(fileURLToPath(import.meta.url), `../fixtures/${name}`)

  it('passes on a clean file', () => {
    expect(run(fx('clean.ts')).exitCode).toBe(0)
  })

  it('fails on a hardcoded `npx ...` string literal', () => {
    const r = run(fx('offender.ts'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain('offender.ts')
    expect(r.output).toMatch(/\bnpx\b/)
  })

  it("ignores `?? 'npx'` fallback expressions", () => {
    expect(run(fx('allowed-fallback.ts')).exitCode).toBe(0)
  })

  it('ignores comments mentioning npx', () => {
    expect(run(fx('allowed-comment.ts')).exitCode).toBe(0)
  })

  it('skips files in __tests__ directories', () => {
    expect(run(fx('__tests__/inside.test.ts')).exitCode).toBe(0)
  })

  it('flags indented `npx <cmd>` lines inside multi-line template literals', () => {
    const r = run(fx('multiline-offender.ts'))
    expect(r.exitCode).toBe(1)
    // Both indented npx lines should be reported
    expect(r.output).toMatch(/multiline-offender\.ts:3/)
    expect(r.output).toMatch(/multiline-offender\.ts:4/)
  })

  it('flags `Usage: npx ...` lines inside multi-line template literals', () => {
    const r = run(fx('wizard-style.ts'))
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/wizard-style\.ts:4/)
  })

  it("flags hardcoded default params like `runner = 'npx'`", () => {
    const r = run(fx('default-param.ts'))
    expect(r.exitCode).toBe(1)
  })

  it('does not flag `npx` used as part of a JS identifier', () => {
    expect(run(fx('identifier.ts')).exitCode).toBe(0)
  })
})
