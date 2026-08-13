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
  lint,
  manifestFiles,
  npmDeclarations,
  report,
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

  it.each([
    'devDependencies',
    'peerDependencies',
    'optionalDependencies',
  ])('reads %s', (table) => {
    expect(pkg({ [table]: { '@cipherstash/eql': '3.0.2' } })[0].table).toBe(
      table,
    )
  })

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
