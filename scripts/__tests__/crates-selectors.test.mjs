import { describe, expect, it } from 'vitest'
import { readSelectorJob, selectedJobs } from './lib/selector.mjs'

/**
 * What the selector jobs of the Rust crate workflows decide for a pull
 * request. Each check's trigger paths list the crates it builds, including
 * their path dependencies in the workspace, and the configuration its tools
 * read. The gates that excluded documentation before still do.
 */

const WORKFLOWS = {
  crap: '.github/workflows/crap-crates.yml',
  fuzz: '.github/workflows/fuzz.yml',
  miri: '.github/workflows/miri.yml',
  udeps: '.github/workflows/udeps.yml',
  crates: '.github/workflows/tests-crates.yml',
  rust: '.github/workflows/tests-rust.yml',
  refresh: '.github/workflows/tests-auth-refresh.yml',
}

/** The jobs a pull request runs, without the two that always run. */
const checks = (relPath, files, options) =>
  selectedJobs(relPath, files, options).filter(
    (id) => id !== 'selector' && id !== 'summary',
  )

describe('the crate workflows', () => {
  it.each(Object.values(WORKFLOWS))('%s has a selector job', (relPath) => {
    expect(readSelectorJob(relPath)).not.toBeNull()
  })
})

describe('the CRAP gate selector', () => {
  const run = (files) => checks(WORKFLOWS.crap, files)

  it('runs the gate of the crate that changed', () => {
    expect(run(['packages/stack-auth/src/lib.rs'])).toEqual([
      'crap-stack-auth',
      'crap-stack-encrypt',
    ])
    expect(run(['packages/stack-encrypt/src/lib.rs'])).toEqual([
      'crap-stack-encrypt',
    ])
  })

  it("runs a gate for a change to that crate's path dependencies", () => {
    expect(run(['packages/stack-kms/src/lib.rs'])).toEqual([
      'crap-stack-encrypt',
    ])
    expect(run(['packages/stack-profile/src/lib.rs'])).toEqual([
      'crap-stack-auth',
      'crap-stack-encrypt',
    ])
  })

  it('skips both gates for documentation and other crates', () => {
    expect(run(['packages/stack-auth/README.md'])).toEqual([])
    expect(run(['packages/stack-guest-abi/src/lib.rs'])).toEqual([])
  })
})

describe('the fuzz selector', () => {
  const run = (files) => checks(WORKFLOWS.fuzz, files)

  it('replays the corpus for a change to a fuzzed crate or its dependencies', () => {
    expect(run(['packages/stack-kms/fuzz/fuzz_targets/a.rs'])).toEqual([
      'fuzz-regression',
    ])
    expect(run(['packages/stack-profile/src/lib.rs'])).toEqual([
      'fuzz-regression',
    ])
    expect(run(['packages/stack-encrypt-derive/src/lib.rs'])).toEqual([
      'fuzz-regression',
    ])
  })

  it('skips the replay for documentation and other crates', () => {
    expect(run(['packages/stack-encrypt/docs/adr/0001-example.md'])).toEqual([])
    expect(run(['packages/stack-guest-abi/src/lib.rs'])).toEqual([])
  })

  it('never runs the campaign on a pull request', () => {
    expect(run(['packages/stack-auth/src/lib.rs'])).not.toContain(
      'fuzz-campaign',
    )
  })
})

describe('the Miri selector', () => {
  const run = (files) => checks(WORKFLOWS.miri, files)

  it('runs Miri for the guest ABI crate only', () => {
    expect(run(['packages/stack-guest-abi/src/lib.rs'])).toEqual([
      'miri-stack-guest-abi',
    ])
    expect(run(['packages/stack-auth/src/lib.rs'])).toEqual([])
    expect(run(['packages/stack-guest-abi/README.md'])).toEqual([])
  })
})

describe('the unused dependencies selector', () => {
  const run = (files) => checks(WORKFLOWS.udeps, files)

  it('runs for any crate of the workspace and the rust pin', () => {
    expect(run(['languages/typescript/packages/auth/src/lib.rs'])).toEqual([
      'udeps',
    ])
    expect(run(['mise.toml'])).toEqual(['udeps'])
  })

  it('skips documentation', () => {
    expect(run(['packages/stack-kms/README.md'])).toEqual([])
  })
})

describe('the Tests (crates) selector', () => {
  const run = (files) => checks(WORKFLOWS.crates, files)

  it('runs only the cargo job for a crate the bindings do not wrap', () => {
    expect(run(['packages/stack-encrypt/src/lib.rs'])).toEqual(['rust'])
    expect(run(['packages/stack-guest-abi/src/lib.rs'])).toEqual(['rust'])
    expect(run(['.config/nextest.toml'])).toEqual(['rust'])
  })

  it('runs both jobs for a crate the bindings wrap', () => {
    expect(run(['packages/stack-auth/src/lib.rs'])).toEqual([
      'node-bindings',
      'rust',
    ])
    // The README is stack-auth's crate docs, so its doctests read it.
    expect(run(['packages/stack-auth/README.md'])).toEqual([
      'node-bindings',
      'rust',
    ])
  })

  it('runs only the bindings job for a change to the pnpm install', () => {
    expect(run(['pnpm-lock.yaml'])).toEqual(['node-bindings'])
    expect(run(['pnpm-workspace.yaml'])).toEqual(['node-bindings'])
  })

  it('runs neither for a change outside the crates', () => {
    expect(run(['languages/typescript/packages/stack/src/index.ts'])).toEqual(
      [],
    )
  })
})

describe('the Tests (Rust) selector', () => {
  const run = (files) => checks(WORKFLOWS.rust, files)

  it('runs for protect-ffi Rust, the EQL crates it builds, and the rust pin', () => {
    for (const file of [
      'languages/typescript/packages/protect-ffi/crates/protect-ffi/src/lib.rs',
      'packages/eql/crates/eql-bindings/src/lib.rs',
      'mise.toml',
    ]) {
      expect(run([file]), file).toEqual(['rust'])
    }
  })

  it('skips protect-ffi TypeScript and the EQL SQL', () => {
    expect(
      run(['languages/typescript/packages/protect-ffi/src/index.ts']),
    ).toEqual([])
    expect(run(['packages/eql/src/v3/schema.sql'])).toEqual([])
  })
})

describe('the auth refresh selector', () => {
  const run = (files, options) => checks(WORKFLOWS.refresh, files, options)

  it('runs the short soak on every pull request', () => {
    expect(run(['README.md'])).toEqual(['short'])
  })

  it('runs the long soak for stack-auth and the crate it builds', () => {
    expect(run(['packages/stack-auth/src/lib.rs'])).toEqual(['long', 'short'])
    expect(run(['packages/stack-profile/src/lib.rs'])).toEqual([
      'long',
      'short',
    ])
  })

  it('runs the long soak on Version Packages', () => {
    expect(
      run(['README.md'], { github: { head_ref: 'changeset-release/main' } }),
    ).toEqual(['long', 'short'])
  })
})
