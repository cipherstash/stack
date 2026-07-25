import { execFileSync } from 'node:child_process'
import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-hardcoded-runners.mjs',
)

function runScript(script, ...targets) {
  try {
    execFileSync(process.execPath, [script, ...targets], { encoding: 'utf8' })
    return { exitCode: 0, output: '' }
  } catch (err) {
    return {
      exitCode: err.status,
      output: String(err.stdout) + String(err.stderr),
    }
  }
}

function run(target) {
  return runScript(SCRIPT, target)
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

// An allowlist entry is a standing exemption. When the file it names is deleted
// — or stops carrying the `npx` literal it was excused for — the entry becomes
// silent dead weight, and the next reader takes it as evidence that the file
// still needs an exemption. `packages/drizzle/src/bin/runner.ts` sat here for
// the two months after 413ca396 deleted its package, and surfaced only because
// a sibling linter happened to start scanning `scripts/` (#772 review, finding
// 15). That sibling can only ever catch the `packages/<name>` shape; this check
// covers every entry, including a stale path inside a live package.
describe('lint-no-hardcoded-runners — allowlist hygiene', () => {
  // A copy alongside the original so `REPO_ROOT` still resolves to the repo.
  const PROBE = resolve(
    fileURLToPath(import.meta.url),
    '../../allowlist-probe.mjs',
  )

  function runWithExtraEntry(entry) {
    const src = readFileSync(SCRIPT, 'utf8').replace(
      'const ALLOWLISTED_PATHS = new Set([',
      `const ALLOWLISTED_PATHS = new Set([\n  '${entry}',`,
    )
    try {
      writeFileSync(PROBE, src)
      return runScript(PROBE)
    } finally {
      rmSync(PROBE, { force: true })
    }
  }

  it('rejects an entry whose file no longer exists', () => {
    const r = runWithExtraEntry('scripts/deleted-helper.mjs')
    expect(r.exitCode).toBe(2)
    expect(r.output).toMatch(/scripts\/deleted-helper\.mjs/)
    expect(r.output).toMatch(/no such file/)
  })

  it('rejects an entry whose file no longer needs the exemption', () => {
    const r = runWithExtraEntry('scripts/vitest.config.mjs')
    expect(r.exitCode).toBe(2)
    expect(r.output).toMatch(/scripts\/vitest\.config\.mjs/)
    expect(r.output).toMatch(/no longer contains/)
  })

  it('accepts the allowlist as it stands', () => {
    const r = runScript(SCRIPT)
    expect(r.exitCode).toBe(0)
  })
})
