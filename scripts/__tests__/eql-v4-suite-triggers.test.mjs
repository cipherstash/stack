import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  cargoPathDependencyClosure,
  cargoPathDependencyWalk,
  eqlV4CodecCrateEntries,
  eqlV4SqlBuildEntries,
  eqlV4SuiteFilterEntries,
} from './lib/eql-v4-suite-inputs.mjs'
import { entryCovers, filterCovers } from './lib/paths-filter.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The protect-ffi migration suites (`migrate-v*-to-v4.test.ts`) re-encrypt
 * through a Rust codec built over `eql-bindings`' v4 modules, and query SQL
 * rendered by `eql-codegen`. No other workflow runs those suites:
 * `test-eql.yml` runs the Rust and SQL suites, not this one. So
 * `integration-protect-ffi.yml` has to start when any of those files change,
 * or a change to v4 target dispatch merges with the end-to-end migration
 * coverage skipped. The entries come from `lib/eql-v4-suite-inputs.mjs`.
 */
const WORKFLOW = '.github/workflows/integration-protect-ffi.yml'

describe('the EQL v4 migration suites trigger on their v4 inputs', () => {
  const { features, entries } = eqlV4SuiteFilterEntries(REPO_ROOT)

  it('derives the v4 modules and the codegen crates', () => {
    // An empty or shrunken derivation would pass every check below.
    expect([...features]).toContain('stack-encrypt')
    expect(entries).toEqual(
      expect.arrayContaining([
        'packages/eql/crates/eql-bindings/src/v4/**',
        'packages/eql/crates/eql-bindings/src/encryption/**',
        'packages/eql/crates/eql-codegen/src/**',
      ]),
    )
  })

  const { on } = readWorkflow(WORKFLOW)
  for (const event of ['push', 'pull_request']) {
    it(`${WORKFLOW} (${event}) triggers on every v4 codec and codegen input`, () => {
      const paths = on?.[event]?.paths ?? []
      const uncovered = entries.filter(
        (entry) => !filterCovers(paths, entry, entryCovers),
      )
      expect(
        uncovered,
        `${WORKFLOW} runs the EQL v4 migration suites, but its \`${event}\` \`paths:\` filter does not list these inputs of the v4 codec or the v4 SQL build. Add each to BOTH copies of the filter.`,
      ).toEqual([])
    })
  }
})

describe('the EQL v4 migration suites trigger on the SQL build inputs outside the crates', () => {
  const entries = eqlV4SqlBuildEntries(REPO_ROOT)

  it('derives every #MISE sources entry that is not under crates/', () => {
    // An empty or shrunken derivation would pass the checks below.
    expect(entries).toEqual(
      expect.arrayContaining([
        'packages/eql/Cargo.lock',
        'packages/eql/Cargo.toml',
        'packages/eql/src/v3/**',
        'packages/eql/tasks/build.sh',
        'packages/eql/tasks/build/ordering.sh',
        'packages/eql/tasks/uninstall-v3.sql',
      ]),
    )
    expect(
      entries.filter((entry) => entry.startsWith('packages/eql/crates/')),
    ).toEqual([])
  })

  const { on } = readWorkflow(WORKFLOW)
  for (const event of ['push', 'pull_request']) {
    it(`${WORKFLOW} (${event}) triggers on every input of the v4 SQL build`, () => {
      const paths = on?.[event]?.paths ?? []
      const uncovered = entries.filter(
        (entry) => !filterCovers(paths, entry, entryCovers),
      )
      expect(
        uncovered,
        `${WORKFLOW} runs the EQL v4 migration suites against SQL that \`tasks/build.sh\` renders from these files, but its \`${event}\` \`paths:\` filter does not list them, so a SQL-only v4 change starts no suite that runs it. Add each to BOTH copies of the filter.`,
      ).toEqual([])
    })
  }
})

describe('the EQL v4 migration suites trigger on the crates the codec compiles', () => {
  const { crates, entries, workspaceManifests } =
    eqlV4CodecCrateEntries(REPO_ROOT)

  it('walks the whole in-tree dependency graph of the codec', () => {
    // The two crates that were missed sit two hops out, one behind
    // `workspace = true` in a target-specific table. A walk that lost either
    // edge would shrink and pass.
    expect(crates).toEqual(
      expect.arrayContaining([
        'packages/stack-encrypt',
        'packages/stack-encrypt-derive',
        'packages/stack-kms',
        'packages/stack-auth',
        'packages/stack-profile',
      ]),
    )
    expect(entries).toEqual(
      expect.arrayContaining([
        'packages/stack-encrypt-derive/src/**',
        'packages/stack-profile/src/**',
      ]),
    )
  })

  it('finds the workspace manifest the out-of-workspace crates inherit from', () => {
    // stack-kms takes stack-auth and stack-profile from the root manifest's
    // [workspace.dependencies], though cargo builds it from the EQL workspace.
    expect(workspaceManifests).toContain('Cargo.toml')
  })

  it('leaves eql-bindings to the finer-grained derivation', () => {
    // Only part of the crate reaches the codec. A whole-source entry here would
    // start this suite on files it never compiles.
    expect(crates).toContain('packages/eql/crates/eql-bindings')
    expect(entries.filter((e) => e.includes('/eql-bindings/'))).toEqual([])
  })

  const { on } = readWorkflow(WORKFLOW)
  for (const event of ['push', 'pull_request']) {
    it(`${WORKFLOW} (${event}) triggers on every in-tree crate the codec compiles`, () => {
      const paths = on?.[event]?.paths ?? []
      const uncovered = entries.filter(
        (entry) => !filterCovers(paths, entry, entryCovers),
      )
      expect(
        uncovered,
        `${WORKFLOW} runs the EQL v4 migration suites through a codec that compiles these in-tree crates, but its \`${event}\` \`paths:\` filter does not list them, so a change confined to one starts no suite that runs it. Add each to BOTH copies of the filter.`,
      ).toEqual([])
    })

    it(`${WORKFLOW} (${event}) triggers on every workspace manifest those crates inherit dependencies from`, () => {
      const paths = on?.[event]?.paths ?? []
      const uncovered = workspaceManifests.filter(
        (manifest) => !filterCovers(paths, manifest, entryCovers),
      )
      expect(
        uncovered,
        `The crates the EQL v4 codec compiles take dependency specs from these manifests' [workspace.dependencies], but the \`${event}\` \`paths:\` filter of ${WORKFLOW} does not list them, so a change confined to one starts no suite that runs the codec. Add each to BOTH copies of the filter.`,
      ).toEqual([])
    })
  }
})

describe('cargoPathDependencyClosure', () => {
  const roots = []
  afterEach(() => {
    for (const root of roots.splice(0)) {
      rmSync(root, { recursive: true, force: true })
    }
  })

  /** A throwaway tree from `{ 'relative/path/Cargo.toml': 'contents' }`. */
  function tree(files) {
    const root = mkdtempSync(join(tmpdir(), 'eql-v4-suite-inputs-'))
    roots.push(root)
    for (const [path, contents] of Object.entries(files)) {
      mkdirSync(dirname(join(root, path)), { recursive: true })
      writeFileSync(join(root, path), contents)
    }
    return root
  }
  const pkg = (name) => `[package]\nname = "${name}"\nversion = "0.1.0"\n`

  it('follows every spelling of a path dependency, transitively', () => {
    const root = tree({
      'start/Cargo.toml': `${pkg('start')}
[dependencies]
inline = { path = "../inline", features = [
  "multi-line",
] }
dotted.path = "../dotted"
registry = "1"
pinned = { version = "1", optional = true }

[build-dependencies]
builder = { path = "../builder" }

[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
targeted = { path = "../targeted", optional = true }

[dependencies.tabled]
path = "../tabled"
`,
      'inline/Cargo.toml': `${pkg('inline')}\n[dependencies]\ndeep = { path = "../deep" } # a comment\n`,
      'deep/Cargo.toml': pkg('deep'),
      'dotted/Cargo.toml': pkg('dotted'),
      'builder/Cargo.toml': pkg('builder'),
      'targeted/Cargo.toml': pkg('targeted'),
      'tabled/Cargo.toml': pkg('tabled'),
    })
    expect(cargoPathDependencyClosure(root, 'start/Cargo.toml')).toEqual([
      'builder',
      'deep',
      'dotted',
      'inline',
      'start',
      'tabled',
      'targeted',
    ])
  })

  it('counts dev-dependencies for the starting crate only', () => {
    // A dependency's own dev-dependencies are not built for a dependent. The
    // derive crate's dev-dependency on stack-encrypt is a real instance.
    const root = tree({
      'start/Cargo.toml': `${pkg('start')}\n[dev-dependencies]\ndep = { path = "../dep" }\n`,
      'dep/Cargo.toml': `${pkg('dep')}\n[dev-dependencies]\ntest-only = { path = "../missing" }\n`,
    })
    expect(cargoPathDependencyClosure(root, 'start/Cargo.toml')).toEqual([
      'dep',
      'start',
    ])
  })

  it('terminates on a cycle', () => {
    const root = tree({
      'a/Cargo.toml': `${pkg('a')}\n[dependencies]\nb = { path = "../b" }\n`,
      'b/Cargo.toml': `${pkg('b')}\n[dependencies]\na = { path = "../a" }\n`,
    })
    expect(cargoPathDependencyClosure(root, 'a/Cargo.toml')).toEqual(['a', 'b'])
  })

  it('resolves workspace = true through the workspace owning the crate', () => {
    // The starting crate's workspace has no entry for `sibling`: the entry
    // belongs to the outer workspace that owns `outer-member`, as the repo root
    // owns stack-kms when the EQL workspace builds it.
    const root = tree({
      'Cargo.toml': `[workspace]
members = ["outer-member"]

[workspace.dependencies]
sibling = { path = "./sibling", version = "1" }
shared = "1"
`,
      'nested/Cargo.toml': '[workspace]\nmembers = ["start"]\n',
      'nested/start/Cargo.toml': `${pkg('start')}\n[dependencies]\nouter-member = { path = "../../outer-member" }\n`,
      'outer-member/Cargo.toml': `${pkg('outer-member')}\n[dependencies]\nsibling = { workspace = true }\nshared.workspace = true\n`,
      'sibling/Cargo.toml': pkg('sibling'),
    })
    expect(cargoPathDependencyClosure(root, 'nested/start/Cargo.toml')).toEqual(
      ['nested/start', 'outer-member', 'sibling'],
    )
  })

  it('reports only the workspace manifests it resolved a dependency through', () => {
    const root = tree({
      'Cargo.toml': `[workspace]
members = ["member"]

[workspace.dependencies]
shared = "1"
`,
      'nested/Cargo.toml': '[workspace]\nmembers = ["start"]\n',
      'nested/start/Cargo.toml': `${pkg('start')}\n[dependencies]\nmember = { path = "../../member" }\n`,
      'member/Cargo.toml': `${pkg('member')}\n[dependencies]\nshared.workspace = true\n`,
    })
    expect(cargoPathDependencyWalk(root, 'nested/start/Cargo.toml')).toEqual({
      crates: ['member', 'nested/start'],
      workspaceManifests: ['Cargo.toml'],
    })
  })

  describe('throws rather than stopping short', () => {
    const start = (deps) => `${pkg('start')}\n[dependencies]\n${deps}\n`

    it('on a path with no manifest behind it', () => {
      const root = tree({
        'start/Cargo.toml': start('gone = { path = "../gone" }'),
      })
      expect(() =>
        cargoPathDependencyClosure(root, 'start/Cargo.toml'),
      ).toThrow(/gone resolves to gone, which has no Cargo.toml/)
    })

    it('on workspace = true with no owning workspace', () => {
      const root = tree({
        'start/Cargo.toml': start('orphan = { workspace = true }'),
      })
      expect(() =>
        cargoPathDependencyClosure(root, 'start/Cargo.toml'),
      ).toThrow(/orphan says workspace = true, but no workspace owns/)
    })

    it('on workspace = true with no entry in that workspace', () => {
      const root = tree({
        'Cargo.toml': '[workspace]\nmembers = ["start"]\n',
        'start/Cargo.toml': start('absent = { workspace = true }'),
      })
      expect(() =>
        cargoPathDependencyClosure(root, 'start/Cargo.toml'),
      ).toThrow(/no \[workspace.dependencies\] entry for it/)
    })

    it('on a spec naming no source', () => {
      const root = tree({
        'start/Cargo.toml': start('odd = { features = ["x"] }'),
      })
      expect(() =>
        cargoPathDependencyClosure(root, 'start/Cargo.toml'),
      ).toThrow(/cannot resolve odd/)
    })

    it('on a line it cannot read', () => {
      const root = tree({
        'start/Cargo.toml': start('what is this'),
      })
      expect(() =>
        cargoPathDependencyClosure(root, 'start/Cargo.toml'),
      ).toThrow(/cannot read "what is this"/)
    })
  })
})
