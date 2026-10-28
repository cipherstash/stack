import { describe, expect, it } from 'vitest'
import { readSelectorJob, selectedJobs } from './lib/selector.mjs'

/**
 * What the Mutants selector job decides for a pull request.
 *
 * The gate mutates the changed lines of stack-auth and stack-encrypt only
 * (`-p stack-auth -p stack-encrypt --in-diff`). A change elsewhere yields no
 * mutants, so the gate would pass without testing anything. The selector
 * skips it instead. Documentation is excluded, as the workflow-level path
 * filter excluded it before the selector replaced that filter.
 */

const WORKFLOW = '.github/workflows/mutants.yml'

const runs = (files) => selectedJobs(WORKFLOW, files).includes('mutants')

describe('the Mutants selector job', () => {
  it('exists', () => {
    expect(readSelectorJob(WORKFLOW)).not.toBeNull()
  })

  it('runs the gate for a change to the code of either crate', () => {
    expect(runs(['packages/stack-auth/src/lib.rs'])).toBe(true)
    expect(runs(['packages/stack-encrypt/src/lib.rs'])).toBe(true)
  })

  it('runs the gate for a change to the toolchain or its configuration', () => {
    for (const file of [
      'Cargo.toml',
      'Cargo.lock',
      'mise.toml',
      'mise.test.toml',
      '.cargo/mutants.toml',
      WORKFLOW,
    ]) {
      expect(runs([file]), file).toBe(true)
    }
  })

  it('skips the gate for documentation in the crates', () => {
    expect(runs(['packages/stack-encrypt/README.md'])).toBe(false)
    expect(runs(['packages/stack-encrypt/docs/adr/0001-example.md'])).toBe(
      false,
    )
    expect(runs(['packages/stack-auth/.env.example'])).toBe(false)
  })

  it('runs the gate when documentation comes with code', () => {
    expect(
      runs([
        'packages/stack-encrypt/README.md',
        'packages/stack-auth/src/a.rs',
      ]),
    ).toBe(true)
  })

  it('skips the gate for a crate it does not mutate', () => {
    expect(runs(['packages/stack-kms/src/lib.rs'])).toBe(false)
    expect(runs(['packages/stack-encrypt-derive/src/lib.rs'])).toBe(false)
    expect(runs(['languages/typescript/packages/stack/src/index.ts'])).toBe(
      false,
    )
  })

  it('always runs the summary job', () => {
    expect(selectedJobs(WORKFLOW, ['README.md'])).toEqual([
      'selector',
      'summary',
    ])
  })
})
