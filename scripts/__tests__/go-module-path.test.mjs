import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'

/**
 * The Go module lives at its stack path. The suite's path named a private
 * repository whose `bindings/go` folder the suite removal deletes, so a
 * `go get` of it can never resolve.
 *
 * `go vet` catches a stale import, but not a stale `go get` line or
 * pkg.go.dev link in a README. The cutover re-export can bring those back in
 * new or changed files, which is why the text check covers every tracked file.
 * `docs/plans/` keeps the old path as history.
 */

const MODULE = 'github.com/cipherstash/stack/languages/golang'
const SUITE_MODULE = 'github.com/cipherstash/cipherstash-suite/bindings/go'
const SELF = 'scripts/__tests__/go-module-path.test.mjs'

function filesNaming(needle) {
  try {
    return execFileSync(
      'git',
      ['grep', '-l', '-F', needle, '--', '.', ':!docs/plans/', `:!${SELF}`],
      { cwd: REPO_ROOT, encoding: 'utf8' },
    )
      .split('\n')
      .filter(Boolean)
  } catch (error) {
    // git grep exits 1 when nothing matches.
    if (error.status === 1) return []
    throw error
  }
}

describe('Go module path', () => {
  it('go.mod declares the stack path', () => {
    const goMod = readFileSync(
      join(REPO_ROOT, 'languages/golang/go.mod'),
      'utf8',
    )
    expect(goMod.split('\n')[0]).toBe(`module ${MODULE}`)
  })

  it('no tracked file outside docs/plans/ names the suite path', () => {
    expect(filesNaming(SUITE_MODULE)).toEqual([])
  })

  it('the text check sees a match when there is one', () => {
    expect(filesNaming(MODULE)).toContain('languages/golang/go.mod')
  })
})
