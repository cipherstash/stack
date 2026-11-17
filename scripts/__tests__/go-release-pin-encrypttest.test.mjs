import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * languages/golang/encrypt/encrypttest is a Go module of its own, so only a
 * program that imports it downloads the test builds of the engine it embeds.
 * Those builds match the SDK's host code at one version. In the tree the
 * module requires the SDK at the zero pseudo-version and replaces it with
 * ../..; a consumer ignores the replace, so the release commit must require
 * the version it tags. scripts/go-release-pin-encrypttest.sh makes that edit,
 * in release-golang.yml's `build` and again in `publish`, whose tree must
 * match the one `build` tested.
 */

const SDK = 'github.com/cipherstash/stack/languages/golang'
const PLACEHOLDER = 'v0.0.0-00010101000000-000000000000'
const GO_MOD = 'languages/golang/encrypt/encrypttest/go.mod'
const SCRIPT = join(REPO_ROOT, 'scripts/go-release-pin-encrypttest.sh')

let dir

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'go-release-pin-'))
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

function pin(version, gomod) {
  return spawnSync('bash', [SCRIPT, version, gomod], { encoding: 'utf8' })
}

describe('the encrypttest go.mod in the tree', () => {
  const text = readFileSync(join(REPO_ROOT, GO_MOD), 'utf8')

  it('is the encrypttest module', () => {
    expect(text.split('\n')[0]).toBe(`module ${SDK}/encrypt/encrypttest`)
  })

  it('requires the SDK at the placeholder the release rewrites', () => {
    expect(text).toContain(`${SDK} ${PLACEHOLDER}`)
  })

  it('builds against the SDK at the same commit', () => {
    expect(text).toMatch(
      new RegExp(`replace ${SDK.replaceAll('.', '\\.')} => \\.\\./\\.\\.\\n`),
    )
  })
})

describe('go-release-pin-encrypttest.sh', () => {
  it('requires the SDK at the released version, and changes nothing else', () => {
    const gomod = join(dir, 'go.mod')
    copyFileSync(join(REPO_ROOT, GO_MOD), gomod)
    const before = readFileSync(gomod, 'utf8')
    const result = pin('0.1.0-rc.6', gomod)
    expect(result.status, result.stderr).toBe(0)
    const after = readFileSync(gomod, 'utf8')
    expect(after).toBe(
      before.replace(`${SDK} ${PLACEHOLDER}`, `${SDK} v0.1.0-rc.6`),
    )
    expect(after).not.toContain(PLACEHOLDER)
  })

  it('pins a single-line require too', () => {
    const gomod = join(dir, 'go.mod')
    writeFileSync(
      gomod,
      `module ${SDK}/encrypt/encrypttest\n\ngo 1.26.10\n\nrequire ${SDK} ${PLACEHOLDER}\n\nreplace ${SDK} => ../..\n`,
    )
    const result = pin('0.2.0', gomod)
    expect(result.status, result.stderr).toBe(0)
    expect(readFileSync(gomod, 'utf8')).toContain(`require ${SDK} v0.2.0\n`)
  })

  it('refuses a go.mod with no placeholder to rewrite, such as one pinned already', () => {
    const gomod = join(dir, 'go.mod')
    copyFileSync(join(REPO_ROOT, GO_MOD), gomod)
    expect(pin('0.1.0-rc.6', gomod).status).toBe(0)
    const pinned = readFileSync(gomod, 'utf8')
    const again = pin('0.1.0-rc.7', gomod)
    expect(again.status).not.toBe(0)
    expect(again.stderr).toContain('exactly once')
    expect(readFileSync(gomod, 'utf8')).toBe(pinned)
  })
})

describe('release-golang.yml pins the module in both jobs, before committing', () => {
  const workflow = readWorkflow('.github/workflows/release-golang.yml')
  const PIN = 'Pin the encrypttest module to this version'

  for (const [job, commitStep] of [
    ['build', 'Stage the release commit and check it as Go will fetch it'],
    ['publish', 'Commit the guests'],
  ]) {
    it(`${job}`, () => {
      const steps = workflow.jobs[job].steps
      const pinAt = steps.findIndex((step) => step.name === PIN)
      const commitAt = steps.findIndex((step) => step.name === commitStep)
      expect(pinAt, `${job} has no "${PIN}" step`).toBeGreaterThanOrEqual(0)
      expect(commitAt).toBeGreaterThan(pinAt)
      const run = String(steps[pinAt].run)
      expect(run).toContain(
        'scripts/go-release-pin-encrypttest.sh "$VERSION"',
      )
      expect(run).toContain(`git add ${GO_MOD}`)
    })
  }

  it('tags every module the release names, the encrypttest module among them', () => {
    const modules = String(workflow.env.MODULES).split(/\s+/).filter(Boolean)
    expect(modules).toEqual([
      'languages/golang',
      'languages/golang/encrypt/encrypttest',
    ])
  })
})
