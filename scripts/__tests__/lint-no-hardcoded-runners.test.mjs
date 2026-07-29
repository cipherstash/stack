import { spawnSync } from 'node:child_process'
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
  const result = spawnSync(process.execPath, [script, ...targets], {
    encoding: 'utf8',
  })
  return {
    exitCode: result.status,
    output: String(result.stdout) + String(result.stderr),
  }
}

function run(target) {
  return runScript(SCRIPT, target)
}

function runWithReaddirError(code, { afterParent = false } = {}) {
  const probe = resolve(
    fileURLToPath(import.meta.url),
    '../../walk-error-probe.mjs',
  )
  const dir = mkdtempSync(join(tmpdir(), 'lint-hardcoded-runners-walk-'))
  const replacement = afterParent
    ? `let readdirCalls = 0
async function readdir() {
  readdirCalls += 1
  if (readdirCalls === 1) {
    return [{ name: 'vanished', isDirectory: () => true }]
  }
  const err = new Error('readdir failed')
  err.code = '${code}'
  throw err
}`
    : `async function readdir() { const err = new Error('readdir failed'); err.code = '${code}'; throw err }`
  const src = readFileSync(SCRIPT, 'utf8').replace(
    "import { readdir } from 'node:fs/promises'",
    replacement,
  )
  try {
    writeFileSync(probe, src)
    return runScript(probe, dir)
  } finally {
    rmSync(probe, { force: true })
    rmSync(dir, { recursive: true, force: true })
  }
}

function runWithReadFileError(code) {
  const probe = resolve(
    fileURLToPath(import.meta.url),
    '../../read-error-probe.mjs',
  )
  const dir = mkdtempSync(join(tmpdir(), 'lint-hardcoded-runners-read-'))
  const src = readFileSync(SCRIPT, 'utf8')
    .replace(
      "import { readFileSync, statSync } from 'node:fs'",
      `import { readFileSync as realReadFileSync, statSync } from 'node:fs'
function readFileSync(path, ...args) {
  if (String(path).endsWith('vanished.ts')) {
    const err = new Error('read failed')
    err.code = '${code}'
    throw err
  }
  return realReadFileSync(path, ...args)
}`,
    )
    .replace(
      "import { readdir } from 'node:fs/promises'",
      "async function readdir() { return [{ name: 'vanished.ts', isDirectory: () => false }] }",
    )
  try {
    writeFileSync(probe, src)
    return runScript(probe, dir)
  } finally {
    rmSync(probe, { force: true })
    rmSync(dir, { recursive: true, force: true })
  }
}

describe('lint-no-hardcoded-runners', () => {
  const fx = (name) =>
    resolve(fileURLToPath(import.meta.url), `../fixtures/${name}`)

  it('passes on a clean file', () => {
    expect(run(fx('clean.ts')).exitCode).toBe(0)
  })

  it('captures stderr from a successful script', () => {
    const dir = mkdtempSync(join(tmpdir(), 'lint-hardcoded-runners-stderr-'))
    const probe = join(dir, 'stderr-probe.mjs')
    try {
      writeFileSync(probe, "process.stderr.write('successful warning\\n')\n")
      const r = runScript(probe)
      expect(r.exitCode).toBe(0)
      expect(r.output).toContain('successful warning')
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
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

  it('skips a directory that vanished after its parent was enumerated', () => {
    const r = runWithReaddirError('ENOENT', { afterParent: true })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('OK')
  })

  it('rethrows unexpected errors encountered while walking', () => {
    const r = runWithReaddirError('EACCES')
    expect(r.exitCode).not.toBe(0)
    expect(r.output).toContain('EACCES')
  })

  it('skips a file that vanished after its directory was enumerated', () => {
    const r = runWithReadFileError('ENOENT')
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('OK')
  })

  it('rethrows unexpected errors reading an enumerated file', () => {
    const r = runWithReadFileError('EACCES')
    expect(r.exitCode).not.toBe(0)
    expect(r.output).toContain('EACCES')
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
