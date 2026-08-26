import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import {
  cargoDeclarations,
  declarationId,
  EXEMPT_DECLARATIONS,
  EXPECTED_DECLARERS,
  EXPECTED_SOURCES,
  lint,
  manifestFiles,
  npmDeclarations,
  report,
  workspaceDeclarations,
} from '../lint-no-eql-registry-pins.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * `scripts/lint-no-eql-registry-pins.mjs` is the guard on Phase 3 of the EQL
 * absorption: `eql-bindings` and `@cipherstash/eql` must resolve from this
 * repo, not from a registry.
 *
 * The linter is a scanner over manifests, so it has the two failure modes every
 * scanner has, and both are silent:
 *
 * 1. It stops matching — a rename, a skip-directory that swallows `packages/`,
 *    a TOML spelling the block reader does not know — and exits 0 having
 *    checked nothing.
 * 2. It matches, but classifies a registry pin as in-tree.
 *
 * So the tests below are mostly about the classifier's edges and about the
 * scan's own floor, not about the happy path. The happy path is one assertion.
 */

const SCRIPT = resolve(
  fileURLToPath(import.meta.url),
  '../../lint-no-eql-registry-pins.mjs',
)

function run(root) {
  try {
    return {
      exitCode: 0,
      output: execFileSync('node', root ? [SCRIPT, root] : [SCRIPT], {
        encoding: 'utf8',
      }),
    }
  } catch (err) {
    return {
      exitCode: err.status,
      output: String(err.stdout) + String(err.stderr),
    }
  }
}

const tempDirs = []
afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

/** A throwaway tree of manifests, for the scan-level tests. */
function tree(files) {
  const root = mkdtempSync(join(tmpdir(), 'eql-pins-'))
  tempDirs.push(root)
  for (const [rel, contents] of Object.entries(files)) {
    const abs = join(root, rel)
    mkdirSync(dirname(abs), { recursive: true })
    writeFileSync(abs, contents)
  }
  return root
}

/** The declarations one `Cargo.toml` body yields, by form. */
const cargoForms = (body) =>
  cargoDeclarations('Cargo.toml', body).map((d) => d.form)

describe('the tree it actually guards', () => {
  it('passes: every EQL dependency resolves in-tree or is exempt', () => {
    const { exitCode, output } = run()
    expect(output).toContain('resolves in-tree')
    expect(exitCode).toBe(0)
  })

  it('sees protect-ffi reaching eql-bindings by path, not by version', () => {
    // The one-line change Phase 3 exists for. Asserted positively rather than
    // via the linter's exit code, because a scan that silently stopped finding
    // this manifest would also exit 0.
    const declaration = lint().declarations.find(
      (d) =>
        d.file === 'packages/protect-ffi/crates/protect-ffi/Cargo.toml' &&
        d.dependency === 'eql-bindings',
    )
    expect(declaration).toBeDefined()
    expect(declaration.form).toBe('path')
    expect(declaration.spec).toContain('eql/crates/eql-bindings')
  })

  it('does not mistake the eql-bindings crate itself for a consumer', () => {
    // `packages/eql/crates/eql-bindings/Cargo.toml` opens `[package]\nname =
    // "eql-bindings"`. A scan keyed on the string rather than on a dependency
    // TABLE flags the crate for depending on itself — a false positive that
    // cannot be fixed, only exempted, which is how exemption lists start
    // filling up with entries nobody can evaluate.
    const ids = lint().ids
    expect(ids).not.toContain(
      'packages/eql/crates/eql-bindings/Cargo.toml :: eql-bindings',
    )
  })

  it('lists the exempt declaration in its success output', () => {
    // An exemption that produces silence is an exemption nobody re-reads.
    expect(run().output).toContain(
      'packages/protect-ffi/integration-tests/package.json',
    )
  })

  it('has a written reason for every exemption', () => {
    for (const [id, reason] of EXEMPT_DECLARATIONS) {
      expect(
        String(reason).trim().length,
        `${id} has no reason`,
      ).toBeGreaterThan(40)
    }
  })

  it('finds every manifest EXPECTED_DECLARERS names', () => {
    // The scan's floor. `lint()` reports this itself; asserted here too so the
    // suite says WHICH id went missing rather than only that exit 2 happened.
    expect(lint().missingExpected).toEqual([])
    // And the floor has to have a floor. `missingExpected` is computed as
    // "expected ids the scan did not see", so an EXPECTED_DECLARERS emptied out
    // — by a bad merge, or by someone clearing it to make a rename go green —
    // satisfies that check trivially and takes the whole guard with it.
    expect(EXPECTED_DECLARERS.length).toBeGreaterThanOrEqual(6)
  })

  it('walks past node_modules and target', () => {
    // Both are full of other packages' manifests, correctly naming registry
    // versions. Reaching into either makes the linter a permanent false alarm,
    // and the natural "fix" is to weaken the classifier.
    const root = tree({
      'node_modules/other/Cargo.toml':
        '[dependencies]\neql-bindings = "=3.0.2"\n',
      'target/package/x/Cargo.toml':
        '[dependencies]\neql-bindings = "=3.0.2"\n',
      'packages/app/package.json': '{"dependencies":{}}',
    })
    expect(manifestFiles(root)).toEqual(['packages/app/package.json'])
  })
})

describe('cargo: what counts as in-tree', () => {
  it('accepts a path dependency', () => {
    expect(
      cargoForms('[dependencies]\neql-bindings = { path = "../eql" }\n'),
    ).toEqual(['path'])
  })

  it('accepts `workspace = true`, which defers to the workspace root', () => {
    // The root's own `[workspace.dependencies]` entry is scanned as a
    // declaration in its own right (below), so the deferral cannot launder a
    // registry pin — it moves the judgement, it does not remove it.
    expect(
      cargoForms('[dependencies]\neql-bindings = { workspace = true }\n'),
    ).toEqual(['workspace'])
  })

  it('rejects an inline table carrying a version', () => {
    expect(
      cargoForms('[dependencies]\neql-bindings = { version = "=3.0.2" }\n'),
    ).toEqual(['version'])
  })

  it('rejects the bare-string spelling', () => {
    expect(cargoForms('[dependencies]\neql-bindings = "3.0.2"\n')).toEqual([
      'version',
    ])
  })

  it('rejects a git dependency', () => {
    // In-tree means THIS tree. A git dep is a different checkout at a different
    // commit, which is the same skew wearing a different hat.
    expect(
      cargoForms(
        '[dependencies]\neql-bindings = { git = "https://github.com/cipherstash/encrypt-query-language" }\n',
      ),
    ).toEqual(['git'])
  })

  it('reads the `[dependencies.eql-bindings]` table form', () => {
    // The spelling a line-oriented scan misses: the dependency name is in the
    // HEADER, and the line that carries the version does not mention it.
    expect(
      cargoForms('[dependencies.eql-bindings]\nversion = "=3.0.2"\n'),
    ).toEqual(['version'])
    expect(
      cargoForms('[dependencies.eql-bindings]\npath = "../eql"\n'),
    ).toEqual(['path'])
  })

  it.each([
    'dev-dependencies',
    'build-dependencies',
    "target.'cfg(unix)'.dependencies",
    'target.x86_64-apple-darwin.dependencies',
    'workspace.dependencies',
  ])('reads [%s]', (table) => {
    expect(cargoForms(`[${table}]\neql-bindings = "=3.0.2"\n`)).toEqual([
      'version',
    ])
  })

  it('ignores a commented-out dependency', () => {
    expect(
      cargoForms('[dependencies]\n# eql-bindings = { version = "=3.0.2" }\n'),
    ).toEqual([])
  })

  it('ignores a version mentioned in a trailing comment', () => {
    // The real manifest carries a comment block explaining the path dep. A
    // reader that does not strip comments would classify prose.
    expect(
      cargoForms(
        '[dependencies]\neql-bindings = { path = "../eql" } # was "=3.0.2"\n',
      ),
    ).toEqual(['path'])
  })

  it('ignores a dependency table that is not a dependency table', () => {
    expect(
      cargoDeclarations(
        'Cargo.toml',
        '[package]\nname = "eql-bindings"\nversion = "3.0.4"\n',
      ),
    ).toEqual([])
  })
})

describe('cargo: the tables that redirect a dependency without declaring one', () => {
  /**
   * `[patch]` and `[replace]` are not dependency tables — they are the tables
   * that say where a dependency RESOLVES FROM, which is precisely the thing
   * this linter is about. A manifest can keep `eql-bindings = { path = … }`
   * word for word and still build against crates.io, or against a git
   * checkout, by adding four lines somewhere else in the same file.
   *
   * They are the Cargo-side twin of `overrides` on the npm side, and that side
   * has been read since the first version of this script for the same reason:
   * an override moves what actually gets built while every specifier in the
   * tree still reads correct.
   *
   * A patch carrying a `path` is benign — it redirects in-tree, which is where
   * the dependency already points. A patch carrying `git` or a version is the
   * skew, so the existing classifier applies unchanged.
   */
  it('reads `[patch.crates-io]`', () => {
    expect(
      cargoForms(
        '[patch.crates-io]\neql-bindings = { git = "https://github.com/cipherstash/encrypt-query-language" }\n',
      ),
    ).toEqual(['git'])
  })

  it('accepts a patch that redirects in-tree', () => {
    // The legitimate use, and the reason this is classified rather than banned
    // outright: a path patch points at the same tree the dependency already
    // resolves from.
    expect(
      cargoForms(
        '[patch.crates-io]\neql-bindings = { path = "../../eql/crates/eql-bindings" }\n',
      ),
    ).toEqual(['path'])
  })

  it('reads a patch keyed by a source URL, not only by `crates-io`', () => {
    // `[patch.<source>]` takes any source cargo knows: the registry by name,
    // or a git source by its URL. Matching the literal string `crates-io`
    // would read the first and walk past the second.
    expect(
      cargoForms(
        '[patch."https://github.com/cipherstash/encrypt-query-language"]\neql-bindings = { version = "3.0.4" }\n',
      ),
    ).toEqual(['version'])
  })

  it('reads the dotted `[patch.crates-io.eql-bindings]` table form', () => {
    // Same spelling trap as `[dependencies.eql-bindings]`: the crate name is in
    // the HEADER and the line carrying the source does not mention it.
    expect(
      cargoForms(
        '[patch.crates-io.eql-bindings]\ngit = "https://github.com/cipherstash/encrypt-query-language"\n',
      ),
    ).toEqual(['git'])
  })

  it('reads `[replace]`, whose key carries a version', () => {
    // Deprecated in favour of `[patch]`, and still honoured by cargo. Its keys
    // are `"<name>:<version>"`, so the bare-name match used everywhere else in
    // this file does not fire.
    expect(
      cargoForms(
        '[replace]\n"eql-bindings:3.0.4" = { git = "https://github.com/cipherstash/encrypt-query-language" }\n',
      ),
    ).toEqual(['git'])
    expect(
      cargoForms('[replace]\n"eql-bindings:3.0.4" = { path = "../eql" }\n'),
    ).toEqual(['path'])
  })

  it('does not mistake a patch for some other crate', () => {
    // The cry-wolf direction. A workspace patching an unrelated crate must not
    // trip this.
    expect(
      cargoForms('[patch.crates-io]\nserde = { path = "../serde" }\n'),
    ).toEqual([])
  })

  it('flags a patch end to end', () => {
    const root = tree({
      'crates/a/Cargo.toml':
        '[dependencies]\neql-bindings = { path = "../../eql" }\n' +
        '[patch.crates-io]\neql-bindings = { git = "https://github.com/cipherstash/encrypt-query-language" }\n',
    })
    // The manifest's own dependency line is correct and stays correct. Only
    // the patch is the offender, which is the whole point of reading it.
    const { offenders } = lint({ root, expected: [], exemptions: new Map() })
    expect(offenders.map((o) => o.form)).toEqual(['git'])
    expect(run(root).exitCode).toBe(1)
  })

  it('reads a patch in `.cargo/config.toml`, which is not a manifest at all', () => {
    // Cargo reads `[patch]` from its CONFIG as well as from a manifest, and a
    // config is not a `Cargo.toml` — so a scan keyed on manifest filenames
    // never opens the file. Same class as `pnpm-workspace.yaml` on the npm
    // side: the one place a tree-wide redirect can be written while every
    // manifest in the tree still reads correct.
    //
    // Not floored in EXPECTED_SOURCES: no such file exists in this repo today,
    // and a floor on a file that does not exist fails on every run.
    const root = tree({
      '.cargo/config.toml':
        '[patch.crates-io]\neql-bindings = { version = "3.0.2" }\n',
    })
    expect(manifestFiles(root)).toContain('.cargo/config.toml')
    expect(run(root).exitCode).toBe(1)
  })

  it('leaves a `config.toml` that is not cargo config alone', () => {
    // The name is common. Only `.cargo/config.toml` is cargo configuration;
    // anything else called `config.toml` belongs to some other tool, and
    // reading it turns this linter into a scanner of arbitrary TOML.
    const root = tree({
      'somewhere/config.toml':
        '[patch.crates-io]\neql-bindings = { version = "3.0.2" }\n',
    })
    expect(manifestFiles(root)).toEqual([])
  })
})

describe('npm: what counts as in-tree', () => {
  const pkg = (json) => npmDeclarations('package.json', JSON.stringify(json))

  it('accepts a workspace specifier', () => {
    expect(
      pkg({ dependencies: { '@cipherstash/eql': 'workspace:^' } })[0],
    ).toMatchObject({ inTree: true, table: 'dependencies' })
  })

  it('rejects a registry version', () => {
    expect(
      pkg({ dependencies: { '@cipherstash/eql': '3.0.2' } })[0],
    ).toMatchObject({ inTree: false, form: 'version' })
  })

  it.each(['devDependencies', 'peerDependencies', 'optionalDependencies'])(
    'reads %s',
    (table) => {
      expect(pkg({ [table]: { '@cipherstash/eql': '3.0.2' } })[0].table).toBe(
        table,
      )
    },
  )

  it('reads resolutions and both overrides spellings', () => {
    // The quietest way back to a registry: every `workspace:^` in the tree
    // still reads correct while the override moves what is installed.
    expect(pkg({ resolutions: { '@cipherstash/eql': '3.0.2' } })).toHaveLength(
      1,
    )
    expect(pkg({ overrides: { '@cipherstash/eql': '3.0.2' } })).toHaveLength(1)
    expect(
      pkg({ pnpm: { overrides: { '@cipherstash/eql': '3.0.2' } } }),
    ).toHaveLength(1)
  })

  it('ignores the package that IS @cipherstash/eql', () => {
    expect(pkg({ name: '@cipherstash/eql', version: '3.0.4' })).toEqual([])
  })

  it('survives a manifest that does not parse', () => {
    expect(npmDeclarations('package.json', '{ not json')).toEqual([])
  })
})

describe('npm: the spellings a name-keyed scan walks past', () => {
  const pkg = (json) => npmDeclarations('package.json', JSON.stringify(json))

  it('reads a NESTED npm override', () => {
    // npm's overrides are a tree, not a flat map: this pins EQL only under
    // `some-pkg`, and a scan that reads `overrides['@cipherstash/eql']` sees an
    // empty result and reports the tree clean.
    const found = pkg({
      overrides: { 'some-pkg': { '@cipherstash/eql': '3.0.4' } },
    })
    expect(found).toHaveLength(1)
    expect(found[0]).toMatchObject({
      table: 'overrides.some-pkg',
      spec: '3.0.4',
      inTree: false,
    })
  })

  it('reads an override nested more than one level deep', () => {
    expect(
      pkg({
        overrides: { a: { b: { '@cipherstash/eql': '3.0.4' } } },
      })[0],
    ).toMatchObject({ table: 'overrides.a.b', inTree: false })
  })

  it("reads npm's `.` self-target spelling", () => {
    // `{"@cipherstash/eql": {".": "3.0.4"}}` pins the package itself and scopes
    // further overrides beneath it. The version is on the CHILD key.
    expect(
      pkg({ overrides: { '@cipherstash/eql': { '.': '3.0.4' } } })[0],
    ).toMatchObject({ spec: '3.0.4', inTree: false })
  })

  it("reads pnpm's `parent>child` override selector", () => {
    expect(
      pkg({ pnpm: { overrides: { 'some-pkg>@cipherstash/eql': '3.0.4' } } })[0],
    ).toMatchObject({ table: 'pnpm.overrides', inTree: false })
  })

  it('reads an override key carrying a version selector', () => {
    expect(
      pkg({ pnpm: { overrides: { '@cipherstash/eql@<3.0.5': '3.0.4' } } })[0],
    ).toMatchObject({ inTree: false })
  })

  it("reads yarn's `**/` resolutions glob", () => {
    expect(
      pkg({ resolutions: { '**/@cipherstash/eql': '3.0.4' } })[0],
    ).toMatchObject({ table: 'resolutions', inTree: false })
  })

  it('reads a selector key whose range itself contains an `@`', () => {
    // pnpm's own override keys never need a second `@` — its ranges are
    // semver, and its `parent>child` selector puts the second name after a
    // `>`, which this key matcher already handles. yarn's `resolutions`
    // descriptors do: `"<name>@npm:<other-name>@<range>"` is how yarn spells a
    // resolution that also aliases, and both names may be scoped.
    //
    // The suffix was `(@[^@]*)?$`, which stops at the first `@` and therefore
    // matched nothing here. Widening it to `(@.*)?$` cannot cry wolf: the
    // boundary that keeps `@cipherstash/eql-extras` out is the `@` itself, and
    // `-extras` is not one — the test below still holds.
    expect(
      pkg({
        resolutions: {
          '@cipherstash/eql@npm:@cipherstash/eql-fork@1.0.0': '1.0.0',
        },
      }),
    ).toHaveLength(1)
  })

  it('does not flag a neighbouring package whose name starts the same', () => {
    // `@cipherstash/eql-extras` is not `@cipherstash/eql`. A prefix match here
    // makes the linter cry wolf, and the fix for a linter that cries wolf is
    // always to weaken it.
    expect(
      pkg({ dependencies: { '@cipherstash/eql-extras': '1.0.0' } }),
    ).toEqual([])
    expect(
      pkg({ overrides: { other: { '@cipherstash/eqlx': '3.0.4' } } }),
    ).toEqual([])
  })

  it('reads a RENAMED dependency whose value aliases the package', () => {
    // The name is on the right-hand side. Keying the scan on the dependency
    // name misses this entirely — it installs @cipherstash/eql@3.0.4 from the
    // registry under another name.
    const found = pkg({
      dependencies: { 'eql-legacy': 'npm:@cipherstash/eql@3.0.4' },
    })
    expect(found).toHaveLength(1)
    expect(found[0]).toMatchObject({
      key: 'eql-legacy',
      form: 'alias',
      inTree: false,
    })
  })

  it('accepts the in-tree spelling of an alias', () => {
    // `workspace:<name>@<range>` is how an aliased dep names a workspace
    // package. It resolves in-tree, so it is not an offender.
    expect(
      pkg({
        dependencies: { 'eql-legacy': 'workspace:@cipherstash/eql@^' },
      })[0],
    ).toMatchObject({ inTree: true, form: 'workspace' })
  })

  it('ignores an alias pointing at some other package', () => {
    expect(pkg({ dependencies: { x: 'npm:lodash@4' } })).toEqual([])
  })

  it('reads an alias hidden in an override', () => {
    expect(
      pkg({ overrides: { 'eql-legacy': 'npm:@cipherstash/eql@3.0.4' } })[0],
    ).toMatchObject({ form: 'alias', inTree: false })
  })

  it('names the declaration by the package, not by the key it was found under', () => {
    // `EXPECTED_DECLARERS` and `EXEMPT_DECLARATIONS` are keyed `<file> ::
    // <dependency>`. If an alias were filed under its alias name, an exemption
    // could never be written for it and the two lists would drift apart from
    // the scan.
    expect(
      declarationId(
        pkg({
          dependencies: { 'eql-legacy': 'npm:@cipherstash/eql@3.0.4' },
        })[0],
      ),
    ).toBe('package.json :: @cipherstash/eql')
  })

  it('reports the offending KEY, so the reader can find the line', () => {
    const { code, err } = report({
      ids: ['x :: y'],
      declarations: [],
      exempted: [],
      staleExemptions: [],
      unreasonedExemptions: [],
      missingExpected: [],
      missingSources: [],
      offenders: [
        {
          file: 'package.json',
          dependency: '@cipherstash/eql',
          key: 'eql-legacy',
          table: 'dependencies',
          spec: 'npm:@cipherstash/eql@3.0.4',
        },
      ],
    })
    expect(code).toBe(1)
    expect(err).toContain('eql-legacy')
  })

  it('flags a nested override end to end', () => {
    const root = tree({
      'package.json': '{"overrides":{"some-pkg":{"@cipherstash/eql":"3.0.4"}}}',
    })
    expect(run(root).exitCode).toBe(1)
  })
})

describe('pnpm-workspace.yaml: the file no manifest scan opens', () => {
  const declarations = (yaml) =>
    workspaceDeclarations('pnpm-workspace.yaml', yaml)

  it('is collected by the walk', () => {
    // The hole this whole block is about: pnpm 10 reads `overrides` from here,
    // and the scan only ever opened `Cargo.toml` and `package.json`.
    const root = tree({ 'pnpm-workspace.yaml': 'packages:\n  - packages/*\n' })
    expect(manifestFiles(root)).toContain('pnpm-workspace.yaml')
  })

  it('reads a top-level `overrides:` entry', () => {
    expect(
      declarations("overrides:\n  '@cipherstash/eql': 3.0.4\n")[0],
    ).toMatchObject({
      file: 'pnpm-workspace.yaml',
      dependency: '@cipherstash/eql',
      table: 'overrides',
      spec: '3.0.4',
      inTree: false,
    })
  })

  it('reads an override written as a version selector', () => {
    // The shape every other override in this repo's file is written in.
    expect(
      declarations("overrides:\n  '@cipherstash/eql@<3.0.5': 3.0.4\n"),
    ).toHaveLength(1)
  })

  it('reads a `parent>child` override', () => {
    expect(
      declarations("overrides:\n  'stash>@cipherstash/eql': 3.0.4\n"),
    ).toHaveLength(1)
  })

  it('accepts a `workspace:` override', () => {
    expect(
      declarations("overrides:\n  '@cipherstash/eql': workspace:^\n")[0],
    ).toMatchObject({ inTree: true })
  })

  it('reads a named catalog entry', () => {
    // A catalog is the other way to move what installs: every manifest keeps
    // saying `catalog:repo` while the version behind it changes here.
    expect(
      declarations("catalogs:\n  repo:\n    '@cipherstash/eql': 3.0.4\n")[0],
    ).toMatchObject({ table: 'catalogs.repo', spec: '3.0.4', inTree: false })
  })

  it('reads the default catalog', () => {
    expect(
      declarations("catalog:\n  '@cipherstash/eql': 3.0.4\n")[0],
    ).toMatchObject({ table: 'catalog', inTree: false })
  })

  it('leaves the rest of the file alone', () => {
    // The real file carries a dozen security overrides and two catalogs. A
    // reader that flagged any of them would be turned off within the week.
    expect(
      declarations(
        [
          'packages:',
          '  - packages/*',
          'catalogs:',
          '  repo:',
          '    typescript: 5.9.3',
          'overrides:',
          "  'next@<15.5.18': '~15.5.18'",
          "  'lodash@<4.18.0': '^4.18.0'",
          'minimumReleaseAge: 10080',
        ].join('\n'),
      ),
    ).toEqual([])
  })

  it('flags a workspace-level override end to end', () => {
    // The mutation check, as a test: plant the pin the linter could not see
    // and confirm it now exits 1.
    const root = tree({
      'pnpm-workspace.yaml':
        "packages:\n  - packages/*\noverrides:\n  '@cipherstash/eql': 3.0.4\n",
      'packages/a/package.json':
        '{"dependencies":{"@cipherstash/eql":"workspace:^"}}',
    })
    expect(run(root).exitCode).toBe(1)
    expect(run(root).output).toContain('pnpm-workspace.yaml')
  })

  it('flags a catalog entry end to end', () => {
    const root = tree({
      'pnpm-workspace.yaml':
        "packages:\n  - packages/*\ncatalogs:\n  repo:\n    '@cipherstash/eql': 3.0.4\n",
    })
    expect(run(root).exitCode).toBe(1)
  })

  it('treats `catalog:` in a manifest as a registry pin, not as a deferral', () => {
    // Cargo's `workspace = true` is accepted because the workspace root's entry
    // is scanned as a declaration in its own right. `catalog:` is NOT given the
    // same treatment: a catalog holds version ranges, so the deferral has no
    // in-tree answer to defer to. Flagging both ends is deliberate.
    expect(
      npmDeclarations(
        'package.json',
        '{"dependencies":{"@cipherstash/eql":"catalog:repo"}}',
      )[0],
    ).toMatchObject({ inTree: false, form: 'catalog' })
  })
})

describe('the new source has a floor of its own', () => {
  it('is satisfied by the real tree', () => {
    expect(lint().missingSources).toEqual([])
    // And the floor needs a floor, for the same reason EXPECTED_DECLARERS does:
    // an emptied list satisfies "nothing missing" trivially.
    expect(EXPECTED_SOURCES).toContain('pnpm-workspace.yaml')
  })

  it('notices a source that is not there at all', () => {
    const root = tree({ 'packages/a/package.json': '{"dependencies":{}}' })
    expect(
      lint({ root, expected: [], exemptions: new Map() }).missingSources,
    ).toEqual(['pnpm-workspace.yaml'])
  })

  it('notices a source that did not parse, rather than reading it as clean', () => {
    // The failure mode this floor exists for. A YAML file that js-yaml refuses
    // contributes no declarations — which is indistinguishable from a file with
    // no overrides in it, and one of those two is a linter that stopped working.
    const root = tree({
      'pnpm-workspace.yaml': 'packages:\n  - a\n   bad indent: [\n',
    })
    expect(
      lint({ root, expected: [], exemptions: new Map() }).missingSources,
    ).toEqual(['pnpm-workspace.yaml'])
  })

  it('notices a source emptied out', () => {
    const root = tree({ 'pnpm-workspace.yaml': '\n# nothing here\n' })
    expect(
      lint({ root, expected: [], exemptions: new Map() }).missingSources,
    ).toEqual(['pnpm-workspace.yaml'])
  })

  it('exits 2 — not 0 — when a source could not be read', () => {
    const { code, err } = report({
      ids: [],
      declarations: [],
      offenders: [],
      exempted: [],
      staleExemptions: [],
      unreasonedExemptions: [],
      missingExpected: [],
      missingSources: ['pnpm-workspace.yaml'],
    })
    expect(code).toBe(2)
    expect(err).toContain('pnpm-workspace.yaml')
  })

  it('reports an unreadable source ahead of any offender it found', () => {
    const { code } = report({
      ids: ['x :: y'],
      declarations: [],
      offenders: [{ file: 'a', dependency: 'b', spec: '"1.0"' }],
      exempted: [],
      staleExemptions: [],
      unreasonedExemptions: [],
      missingExpected: [],
      missingSources: ['pnpm-workspace.yaml'],
    })
    expect(code).toBe(2)
  })
})

describe('the scan reports what it finds', () => {
  it('flags a registry pin anywhere in a tree', () => {
    const root = tree({
      'crates/a/Cargo.toml': '[dependencies]\neql-bindings = "=3.0.2"\n',
      'packages/b/package.json':
        '{"dependencies":{"@cipherstash/eql":"3.0.4"}}',
      'packages/c/package.json':
        '{"dependencies":{"@cipherstash/eql":"workspace:^"}}',
    })
    const { offenders } = lint({ root, expected: [], exemptions: new Map() })
    expect(offenders.map(declarationId)).toEqual([
      'crates/a/Cargo.toml :: eql-bindings',
      'packages/b/package.json :: @cipherstash/eql',
    ])
    expect(run(root).exitCode).toBe(1)
  })

  it('exempts a declaration named in the exemption map, and only that one', () => {
    const root = tree({
      'a/package.json': '{"dependencies":{"@cipherstash/eql":"3.0.2"}}',
      'b/package.json': '{"dependencies":{"@cipherstash/eql":"3.0.2"}}',
    })
    const result = lint({
      root,
      expected: [],
      exemptions: new Map([['a/package.json :: @cipherstash/eql', 'because']]),
    })
    expect(result.exempted.map(declarationId)).toEqual([
      'a/package.json :: @cipherstash/eql',
    ])
    expect(result.offenders.map(declarationId)).toEqual([
      'b/package.json :: @cipherstash/eql',
    ])
  })
})

describe('the linter fails when its own configuration goes stale', () => {
  // These branches cannot fire against the real tree — that is the point of
  // them — so they are driven through `report()`, the same mapping the CLI
  // uses. Asserting on `lint()` alone would prove the condition is DETECTED
  // without proving anything about what happens next, and "detected, then
  // exit 0" is the failure shape this whole branch is about.
  const clean = {
    ids: ['x :: y'],
    declarations: [],
    offenders: [],
    exempted: [],
    staleExemptions: [],
    unreasonedExemptions: [],
    missingExpected: [],
    missingSources: [],
  }

  it('exits 2 — not 1 — when an expected declarer disappears', () => {
    const { code, err } = report({
      ...clean,
      missingExpected: ['packages/stack/package.json :: @cipherstash/eql'],
    })
    expect(code).toBe(2)
    expect(err).toContain('packages/stack/package.json')
    // The scan's own output, so a rename is a copy rather than a re-derivation.
    expect(err).toContain('x :: y')
  })

  it('exits 2 when an exemption no longer describes anything', () => {
    const { code, err } = report({ ...clean, staleExemptions: ['gone :: dep'] })
    expect(code).toBe(2)
    expect(err).toContain('needs an exemption')
  })

  it('exits 2 when an exemption has no reason written', () => {
    const { code, err } = report({
      ...clean,
      unreasonedExemptions: ['a :: b'],
    })
    expect(code).toBe(2)
    expect(err).toContain('no reason written')
  })

  it('reports a broken scan ahead of any offender it found', () => {
    // A scan that lost its subject cannot be trusted to have found every
    // offender either. Reporting "1 registry pin" from a broken scan sends the
    // reader to fix the wrong thing, and — worse — the fix makes it exit 0.
    const { code } = report({
      ...clean,
      offenders: [{ file: 'a', dependency: 'b', spec: '"1.0"' }],
      missingExpected: ['gone :: dep'],
    })
    expect(code).toBe(2)
  })

  it('detects an exemption whose manifest is gone', () => {
    // `report()` covers the exit code; this covers `lint()` producing the
    // input, so the two halves cannot pass while disagreeing about the shape
    // of the field between them.
    const root = tree({ 'a/package.json': '{"dependencies":{}}' })
    expect(
      lint({
        root,
        expected: [],
        exemptions: new Map([['b/package.json :: @cipherstash/eql', 'stale']]),
      }).staleExemptions,
    ).toEqual(['b/package.json :: @cipherstash/eql'])
  })

  it('detects an exemption whose manifest went in-tree', () => {
    // The case that will actually happen. `integration-tests` is exempt
    // because it installs with `npm ci` and cannot resolve `workspace:`;
    // absorbing it into the pnpm workspace is a scheduled follow-up. On that
    // day the manifest still DECLARES `@cipherstash/eql` — it just no longer
    // needs excusing — so an existence-based staleness check would keep
    // passing and leave a standing permission behind. Mutation-checked against
    // the real tree: flipping that pin to `workspace:^` moved the linter from
    // exit 0 to exit 2, where the looser spelling had left it at 0.
    const root = tree({
      'a/package.json': '{"dependencies":{"@cipherstash/eql":"workspace:^"}}',
    })
    const result = lint({
      root,
      expected: [],
      exemptions: new Map([['a/package.json :: @cipherstash/eql', 'obsolete']]),
    })
    expect(result.offenders).toEqual([])
    expect(result.staleExemptions).toEqual([
      'a/package.json :: @cipherstash/eql',
    ])
  })

  it('exits 2 on a root that does not exist', () => {
    expect(run(join(tmpdir(), 'eql-pins-does-not-exist')).exitCode).toBe(2)
  })
})

describe('something actually runs it', () => {
  // The rule this branch keeps rediscovering: a check that arrives as a file
  // and executes on no event reads exactly like a check that passes. The
  // linter is not reachable from `pnpm test` (it is not a package task) and
  // not from `test:scripts` (that runs THIS file, not the script), so CI is
  // the only thing that invokes it.
  const SCRIPT_ENTRY = 'lint:eql-pins'

  it('is wired to a root package.json script', () => {
    const scripts = JSON.parse(
      execFileSync(
        'node',
        [
          '-e',
          'process.stdout.write(require("./package.json").scripts && JSON.stringify(require("./package.json").scripts))',
        ],
        {
          cwd: REPO_ROOT,
          encoding: 'utf8',
        },
      ),
    )
    expect(scripts[SCRIPT_ENTRY]).toBe(
      'node scripts/lint-no-eql-registry-pins.mjs',
    )
  })

  it('is invoked by a workflow GitHub reads', () => {
    const invoking = workflowFiles().filter((rel) => {
      const wf = readWorkflow(rel)
      return Object.values(wf?.jobs ?? {}).some((job) =>
        (Array.isArray(job?.steps) ? job.steps : []).some((step) =>
          new RegExp(`(^|\\s)pnpm run ${SCRIPT_ENTRY}(\\s|$)`).test(
            String(step?.run ?? ''),
          ),
        ),
      )
    })
    expect(
      invoking,
      `No root workflow runs \`pnpm run ${SCRIPT_ENTRY}\`. The linter exists, is tested, and guards nothing.`,
    ).not.toEqual([])
  })
})

/**
 * The remediation this linter prints is the only instruction most readers will
 * follow, so it has to name a specifier that is actually correct for the
 * declaration it is scolding.
 *
 * `workspace:^` and `workspace:*` both satisfy this linter — it only asks that
 * the specifier resolve in-tree. But they pack DIFFERENTLY into a published
 * tarball: pnpm rewrites `workspace:^` to a caret RANGE and `workspace:*` to
 * the dependency's EXACT version. For a RUNTIME dependency on a package this
 * repo does not yet publish, a range is the whole problem back again — a
 * customer's install resolves any later version published from the other
 * repository, while the Rust that emits payloads stays pinned in-tree. That is
 * the emit/store skew both halves of this guard exist to prevent, arriving
 * through the packed tarball rather than through the manifest.
 *
 * So the remediation must recommend the exact-packing form. This test is here
 * because the text said `workspace:^` for exactly as long as the tree did, and
 * fixing the tree without fixing the advice leaves the linter teaching the
 * mistake it just caught.
 */
describe('the remediation names a specifier that packs exact', () => {
  const remediation = () =>
    report({
      offenders: [
        {
          file: 'packages/cli/package.json',
          table: 'dependencies',
          dependency: '@cipherstash/eql',
          spec: '3.0.5',
        },
      ],
      ids: ['packages/cli/package.json [dependencies] @cipherstash/eql'],
      exempted: [],
      missingSources: [],
      missingExpected: [],
      missingDeclarers: [],
      staleExemptions: [],
      unreasonedExemptions: [],
    }).err ?? ''

  it('tells the reader to write `workspace:*`', () => {
    expect(remediation()).toContain('"@cipherstash/eql": "workspace:*"')
  })

  it('does not hand back the range-packing form as the fix', () => {
    const npmAdvice = remediation()
      .split('\n')
      .filter((line) => line.includes('@cipherstash/eql'))
      .join('\n')
    expect(npmAdvice).not.toContain('workspace:^')
  })
})
