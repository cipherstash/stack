import { describe, expect, it } from 'vitest'
import { readSelectorJob, selectedJobs } from './lib/selector.mjs'

/**
 * What the Tests (Go) selector job decides for a pull request.
 *
 * `wasi-check` builds the stack crates and both WASI guests, and runs the Go
 * tests against them. `go-binding-cross` and `live` need it, so they run when
 * it runs. `go-lint` needs no guests, so only the Go module and its tool pins
 * start it.
 */

const WORKFLOW = '.github/workflows/tests-golang.yml'

const run = (files) =>
  selectedJobs(WORKFLOW, files).filter(
    (id) => id !== 'selector' && id !== 'summary',
  )

const ALL = ['go-binding-cross', 'go-lint', 'live', 'wasi-check']
const GUEST_CHAIN = ['go-binding-cross', 'live', 'wasi-check']

describe('the Tests (Go) selector job', () => {
  it('exists', () => {
    expect(readSelectorJob(WORKFLOW)).not.toBeNull()
  })

  it('runs every job for a change to the Go module', () => {
    expect(run(['languages/golang/encrypt/encrypt.go'])).toEqual(ALL)
    expect(run(['mise.toml'])).toEqual(ALL)
  })

  it('skips the lint for a change to a crate the guests build', () => {
    expect(run(['packages/stack-encrypt/src/lib.rs'])).toEqual(GUEST_CHAIN)
    expect(run(['packages/eql/crates/eql-bindings/src/lib.rs'])).toEqual(
      GUEST_CHAIN,
    )
    expect(run(['.github/actions/require-cs-secrets/action.yml'])).toEqual(
      GUEST_CHAIN,
    )
  })

  it('skips every job for documentation and unrelated code', () => {
    expect(run(['languages/golang/README.md'])).toEqual([])
    expect(run(['packages/eql/src/v3/schema.sql'])).toEqual([])
    expect(run(['languages/typescript/packages/stack/src/index.ts'])).toEqual(
      [],
    )
  })
})
