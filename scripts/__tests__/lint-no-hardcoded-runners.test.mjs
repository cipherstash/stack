import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
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

  // `statSync` on a missing target threw uncaught: exit 1 plus a raw stack
  // trace, indistinguishable from "found a hardcoded npx" to anything reading
  // the exit code. Exit 2 means the linter could not run.
  it('exits 2 when a target does not exist', () => {
    const r = run(fx('no-such-fixture.ts'))
    expect(r.exitCode).toBe(2)
    expect(r.output).toContain('no-such-fixture.ts')
    expect(r.output).not.toMatch(/at ModuleJob/)
  })

  // Matches the sibling linter: a target outside the repo rendered as a
  // `../../../../..` chain out of the root instead of naming the file.
  it('renders an absolute path for an offender outside the repo root', () => {
    const dir = mkdtempSync(join(tmpdir(), 'lint-hardcoded-runners-'))
    try {
      const file = join(dir, 'outside.ts')
      writeFileSync(file, "export const cmd = 'npx drizzle-kit generate'\n")
      const r = run(file)
      expect(r.exitCode).toBe(1)
      expect(r.output).toContain(file)
      expect(r.output).not.toMatch(/\.\.\//)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
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
