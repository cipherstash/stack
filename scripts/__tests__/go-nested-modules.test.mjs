import { spawnSync } from 'node:child_process'
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `./...` stops at a directory with its own go.mod, so every tool that walks
 * the Go module also runs in each nested module. scripts/go-nested-modules.sh
 * is the one list; these tests hold the list and the tools that read it.
 */

const LISTER = join(REPO_ROOT, 'scripts/go-nested-modules.sh')

function list(dir) {
  const result = spawnSync('bash', [LISTER, dir], { encoding: 'utf8' })
  expect(result.status, result.stderr).toBe(0)
  return result.stdout.split('\n').filter(Boolean)
}

describe('go-nested-modules.sh', () => {
  it('lists the modules nested in languages/golang', () => {
    expect(list(join(REPO_ROOT, 'languages/golang'))).toEqual([
      'cmd/sqlc-gen-stash',
      'encrypt/encrypttest',
      'encrypt/example',
    ])
  })

  it('leaves out the module itself and any module under testdata', () => {
    const root = mkdtempSync(join(tmpdir(), 'go-nested-'))
    try {
      for (const path of [
        'go.mod',
        'a/go.mod',
        'b/c/go.mod',
        'b/testdata/x/go.mod',
      ]) {
        mkdirSync(dirname(join(root, path)), { recursive: true })
        writeFileSync(join(root, path), 'module x\n')
      }
      expect(list(root)).toEqual(['a', 'b/c'])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

describe('every tool that walks the Go module reads the list', () => {
  it('go-binding-test.sh, for vet and test', () => {
    const script = readFileSync(
      join(REPO_ROOT, 'scripts/go-binding-test.sh'),
      'utf8',
    )
    expect(script).toContain('"$scripts/go-nested-modules.sh" | while')
  })

  it('the go:lint task', () => {
    const mise = readFileSync(join(REPO_ROOT, 'mise.toml'), 'utf8')
    const lint = mise.slice(mise.indexOf('[tasks."go:lint"]'))
    expect(lint.slice(0, lint.indexOf('\n[tasks.'))).toContain(
      '../../scripts/go-nested-modules.sh | while',
    )
  })

  for (const [job, step] of [
    ['wasi-check', 'Generated code is committed'],
    ['live', 'Go live tests'],
  ]) {
    it(`tests-golang.yml ${job}: ${step}`, () => {
      const steps = readWorkflow('.github/workflows/tests-golang.yml').jobs[job]
        .steps
      const found = steps.find((s) => s.name === step)
      expect(found, step).toBeDefined()
      expect(String(found.run)).toContain(
        '../../scripts/go-nested-modules.sh | while',
      )
    })
  }
})
