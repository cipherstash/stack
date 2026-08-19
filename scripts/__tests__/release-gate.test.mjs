import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import {
  classify,
  packedRange,
  publishBlockers,
  satisfies,
  unpublished,
  workspaceManifests,
  workspacePackagePatterns,
} from '../release-gate.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The gate decides what a push to `main` still has to publish, and it is
 * LOAD-BEARING rather than a cost control — see the header of
 * `scripts/release-gate.mjs`. A false negative skips the native matrix, and
 * `changeset publish` then packs the six platform workspaces without their
 * `index.node` and publishes them.
 */

const FFI = '@cipherstash/protect-ffi'
const PLATFORM = '@cipherstash/protect-ffi-darwin-arm64'

describe('unpublished', () => {
  it('reports a package whose committed version is not on the registry', () => {
    expect(
      unpublished([{ name: FFI, version: '0.32.0' }], () => ['0.31.0']),
    ).toEqual([FFI])
  })

  it('reports nothing when the committed version is already published', () => {
    // The basis of the whole ordered-publisher design: a release is a no-op for
    // anything already on the registry, which is why publishing the FFI
    // tarballs first makes `changeset publish` skip them.
    expect(
      unpublished([{ name: FFI, version: '0.31.0' }], () => ['0.31.0']),
    ).toEqual([])
  })

  it('treats a registry 404 as unpublished', () => {
    // A name that has never been published; `null` is the 404.
    expect(
      unpublished([{ name: 'new-pkg', version: '1.0.0' }], () => null),
    ).toEqual(['new-pkg'])
  })

  it('skips private packages', () => {
    expect(
      unpublished(
        [{ name: 'bench', version: '1.0.0', private: true }],
        () => null,
      ),
    ).toEqual([])
  })

  it('propagates a lookup error instead of reporting "nothing to publish"', () => {
    // THE load-bearing case. A network, auth or rate-limit failure must fail
    // the gate — reading it as "already published" skips the artifact build and
    // lets changesets publish binary-less platform packages.
    const boom = () => {
      throw new Error('npm view failed: ETIMEDOUT')
    }
    expect(() => unpublished([{ name: FFI, version: '0.32.0' }], boom)).toThrow(
      /ETIMEDOUT/,
    )
  })

  it('looks each package up once, and only the publishable ones', () => {
    // `npm view` is a network round trip per package. The private skip has to
    // happen BEFORE the lookup, not after it: a private package has no registry
    // entry, so looking one up costs a request to be told 404 and then ignored.
    const asked = []
    const lookup = (name) => {
      asked.push(name)
      return ['1.0.0']
    }
    unpublished(
      [
        { name: 'a', version: '1.0.0' },
        { name: 'secret', version: '1.0.0', private: true },
        { name: 'b', version: '2.0.0' },
      ],
      lookup,
    )
    expect(asked).toEqual(['a', 'b'])
  })
})

describe('workspacePackagePatterns', () => {
  const SOURCE = readFileSync(join(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8')

  it('reads the same patterns a YAML parser does', () => {
    // THE ORACLE. The gate parses `packages:` with node builtins so its job
    // needs no install — which only holds while the hand parse and real YAML
    // agree about THIS file. js-yaml is a devDependency and available here, so
    // the divergence fails on the pull request instead of narrowing the gate
    // during a release.
    expect(workspacePackagePatterns(SOURCE)).toEqual(yaml.load(SOURCE).packages)
  })

  it('keeps the nested platform packages, which `packages/*` does not cover', () => {
    // The six platform packages sit a level deeper than the glob above them.
    // Losing this entry is the concrete shape of a narrowed gate: six
    // unpublished packages reported as nothing to publish.
    expect(workspacePackagePatterns(SOURCE)).toContain(
      'packages/protect-ffi/platforms/*',
    )
  })

  it('stops at the next top-level key', () => {
    expect(
      workspacePackagePatterns(
        'packages:\n  - a/*\n  - b\n\ncatalogs:\n  repo:\n    tsup: 1.0.0\n',
      ),
    ).toEqual(['a/*', 'b'])
  })

  it('ignores comments and quotes, inline and on their own line', () => {
    expect(
      workspacePackagePatterns(
        'packages:\n  # why\n  - \'a/*\' # trailing\n  - "b"\n',
      ),
    ).toEqual(['a/*', 'b'])
  })

  it('throws rather than returning a short list it could not parse', () => {
    // Every failure mode here fails loudly — see the script header. A pattern
    // silently dropped is a package never looked up.
    // Flow style is valid YAML this parse does not read, so the block header
    // never matches and it throws — the direction that fails a release rather
    // than narrowing one. The oracle test above is what catches the day
    // pnpm-workspace.yaml is rewritten this way.
    expect(() => workspacePackagePatterns('packages: [a, b]\n')).toThrow(
      /no `packages:` key/,
    )
    expect(() =>
      workspacePackagePatterns('packages:\n  - a/*\n  not-a-list-item\n'),
    ).toThrow(/unparsable/)
    expect(() => workspacePackagePatterns('catalogs:\n  repo: {}\n')).toThrow(
      /no `packages:` key/,
    )
    expect(() => workspacePackagePatterns('packages:\ncatalogs:\n')).toThrow(
      /no `packages:` patterns/,
    )
  })
})

describe('classify', () => {
  it('flags ffi when the wrapper is unpublished', () => {
    expect(classify([FFI])).toEqual({ ffi: true, js: false })
  })

  it('flags ffi when only a platform package is unpublished', () => {
    // The fixed group moves all seven together, but a partially-failed publish
    // can leave one behind — that still needs the matrix.
    expect(classify([PLATFORM])).toEqual({ ffi: true, js: false })
  })

  it('flags js for an ordinary Stack release', () => {
    expect(classify(['@cipherstash/stack', 'stash'])).toEqual({
      ffi: false,
      js: true,
    })
  })

  it('flags both when a release spans them', () => {
    expect(classify([FFI, '@cipherstash/stack'])).toEqual({
      ffi: true,
      js: true,
    })
  })

  it('flags neither when nothing is unpublished', () => {
    // The common case: any push to main that is not a merged Version PR.
    expect(classify([])).toEqual({ ffi: false, js: false })
  })
})

/**
 * WHAT ARMS A RELEASE THAT CANNOT SUCCEED.
 *
 * `changeset publish` publishes every public workspace package whose committed
 * version is absent from npm — changeset or no changeset. In the installed
 * 2.31.0 it does that with no dependency ordering (`Promise.all`) and
 * `publishAPackage` RETURNS a result rather than throwing, so one package's
 * failed publish does not stop its siblings. A package that cannot publish
 * therefore does not abort the release; it just does not arrive, and everything
 * that depends on it ships pointing at a version nobody can install.
 *
 * That is not hypothetical here. `@cipherstash/eql` was hand-bumped to 3.0.5 in
 * the workspace while npm's newest is 3.0.4 and its trusted publisher still
 * names `cipherstash/encrypt-query-language` — so its publish from this
 * repository is rejected, while `packages/cli` and `packages/stack-prisma`
 * carry `"@cipherstash/eql": "workspace:^"` in their RUNTIME dependencies,
 * which pnpm rewrites to `^3.0.5` at pack time. A range no published version
 * satisfies, in a tarball that publishes fine.
 */

const EQL = '@cipherstash/eql'

describe('packedRange', () => {
  it('resolves the three bare protocol forms the way pnpm does', () => {
    // `workspace:*` is an EXACT pin, not a wildcard — the distinction the whole
    // check turns on, since it makes the range unsatisfiable by anything but
    // the one version.
    expect(packedRange('workspace:*', '1.5.0')).toBe('1.5.0')
    expect(packedRange('workspace:^', '1.5.0')).toBe('^1.5.0')
    expect(packedRange('workspace:~', '1.5.0')).toBe('~1.5.0')
  })

  it('passes an explicit range through verbatim', () => {
    expect(packedRange('workspace:^1.0.0', '1.5.0')).toBe('^1.0.0')
    expect(packedRange('workspace:1.2.3', '1.5.0')).toBe('1.2.3')
  })

  it('ignores a specifier that is not the workspace protocol', () => {
    // Registry ranges are somebody else's problem: npm resolves them itself.
    expect(packedRange('^1.0.0', '1.5.0')).toBeNull()
    expect(packedRange('catalog:repo', '1.5.0')).toBeNull()
  })
})

describe('satisfies', () => {
  it('reads an exact pin', () => {
    expect(satisfies('1.5.0', '1.5.0')).toBe(true)
    expect(satisfies('1.5.1', '1.5.0')).toBe(false)
  })

  it('reads caret, including the 0.x and 0.0.x narrowings', () => {
    expect(satisfies('1.9.9', '^1.5.0')).toBe(true)
    expect(satisfies('2.0.0', '^1.5.0')).toBe(false)
    expect(satisfies('1.4.9', '^1.5.0')).toBe(false)
    // ^0.5.0 does NOT admit 0.6.0 — the case that decides whether
    // `@cipherstash/protect-ffi@0.31.0`'s siblings are read correctly.
    expect(satisfies('0.5.9', '^0.5.0')).toBe(true)
    expect(satisfies('0.6.0', '^0.5.0')).toBe(false)
    expect(satisfies('0.0.4', '^0.0.3')).toBe(false)
  })

  it('reads tilde', () => {
    expect(satisfies('1.5.9', '~1.5.0')).toBe(true)
    expect(satisfies('1.6.0', '~1.5.0')).toBe(false)
  })

  it('does not let a prerelease satisfy a stable range', () => {
    // THE ONE THAT DECIDES THIS REPO'S ANSWER. npm carries
    // `@cipherstash/eql@3.0.0-alpha.2` and friends, and a naive comparison puts
    // some of them inside `^3.0.5`'s window — which would report the range as
    // satisfiable and wave the whole defect through.
    expect(satisfies('3.1.0-alpha.1', '^3.0.5')).toBe(false)
    expect(satisfies('3.0.0-alpha.2', '^3.0.0')).toBe(false)
    // …while a prerelease of the range's OWN tuple still counts, per semver.
    expect(satisfies('3.0.5-rc.2', '^3.0.5-rc.1')).toBe(true)
  })

  it('throws on a range it cannot read, rather than guessing', () => {
    // Every failure mode in this file fails loudly — see the script header. A
    // range read as "unsatisfiable" would freeze a release that is fine; one
    // read as "satisfiable" would publish the broken tarball.
    expect(() => satisfies('1.0.0', '>=1.0.0 <2.0.0')).toThrow(/range/i)
    expect(() => satisfies('1.0.0', '1.x')).toThrow(/range/i)
  })
})

describe('publishBlockers', () => {
  /** A registry where nothing has ever been published. */
  const empty = () => null

  it('blocks a frozen package whose committed version is not on npm', () => {
    // CHECK A. `changeset publish` will attempt this package because its
    // version is absent, and the attempt is rejected — npm trusted publishing
    // is bound to a repository, and this one is not it.
    const blockers = publishBlockers({
      manifests: [
        { name: EQL, version: '3.0.5', private: false, workspaceDeps: [] },
      ],
      lookup: () => ['3.0.4'],
      frozen: new Map([[EQL, 'publisher not repointed yet']]),
    })
    expect(blockers.map((b) => b.kind)).toEqual(['frozen-publisher'])
    expect(blockers[0].package).toBe(EQL)
  })

  it('lets a frozen package through once its committed version IS on npm', () => {
    // The state the seven protect-ffi packages are in, and the unstated
    // assumption `scripts/lint-no-ffi-changeset.mjs` rests on: at the published
    // version, `changeset publish` skips them and the frozen publisher never
    // matters. This is that assumption, checked.
    expect(
      publishBlockers({
        manifests: [
          { name: EQL, version: '3.0.4', private: false, workspaceDeps: [] },
        ],
        lookup: () => ['3.0.4'],
        frozen: new Map([[EQL, 'publisher not repointed yet']]),
      }),
    ).toEqual([])
  })

  it('blocks a runtime range that only a frozen package could satisfy', () => {
    // CHECK B, and the blast radius. `stash` publishes fine; it just ships a
    // dependency on a version that will never exist.
    const blockers = publishBlockers({
      manifests: [
        { name: EQL, version: '3.0.5', private: false, workspaceDeps: [] },
        {
          name: 'stash',
          version: '1.0.1',
          private: false,
          workspaceDeps: [
            { table: 'dependencies', name: EQL, spec: 'workspace:^' },
          ],
        },
      ],
      lookup: (name) => (name === EQL ? ['3.0.4'] : ['1.0.0']),
      frozen: new Map([[EQL, 'publisher not repointed yet']]),
    })
    const range = blockers.find((b) => b.kind === 'frozen-dependency')
    expect(range).toBeDefined()
    expect(range.package).toBe('stash')
    expect(range.dependency).toBe(EQL)
    expect(range.range).toBe('^3.0.5')
  })

  it('allows a range only this same release will satisfy, when the dep can publish', () => {
    // THE FALSE POSITIVE THAT WOULD MAKE THIS GATE UNUSABLE. Every ordinary
    // release of this repo moves the six-package fixed group together, so at
    // gate time `@cipherstash/stack-drizzle@1.0.1` depends on
    // `@cipherstash/stack@1.0.1` and NEITHER is on npm yet. Failing that would
    // freeze the repo permanently rather than catch anything.
    expect(
      publishBlockers({
        manifests: [
          {
            name: 'stack',
            version: '1.0.1',
            private: false,
            workspaceDeps: [],
          },
          {
            name: 'drizzle',
            version: '1.0.1',
            private: false,
            workspaceDeps: [
              { table: 'dependencies', name: 'stack', spec: 'workspace:*' },
            ],
          },
        ],
        lookup: () => ['1.0.0'],
        frozen: new Map(),
      }),
    ).toEqual([])
  })

  it('blocks a runtime dependency on a package that is never published', () => {
    // `@cipherstash/test-kit` is `private: true`. A runtime `workspace:*` on it
    // packs a range for a package with no registry entry at all — the same
    // broken install, arrived at a different way.
    const blockers = publishBlockers({
      manifests: [
        {
          name: 'test-kit',
          version: '0.0.1',
          private: true,
          workspaceDeps: [],
        },
        {
          name: 'stack',
          version: '1.0.0',
          private: false,
          workspaceDeps: [
            { table: 'dependencies', name: 'test-kit', spec: 'workspace:*' },
          ],
        },
      ],
      lookup: empty,
      frozen: new Map(),
    })
    expect(blockers.map((b) => b.kind)).toEqual(['private-dependency'])
  })

  it('blocks a hand-written range the workspace version cannot satisfy', () => {
    // `workspace:^2.0.0` against a 1.x member. pnpm writes it out verbatim, so
    // nothing downstream notices; it is simply a manifest that cannot resolve.
    const blockers = publishBlockers({
      manifests: [
        { name: 'stack', version: '1.0.0', private: false, workspaceDeps: [] },
        {
          name: 'drizzle',
          version: '1.0.0',
          private: false,
          workspaceDeps: [
            { table: 'dependencies', name: 'stack', spec: 'workspace:^2.0.0' },
          ],
        },
      ],
      lookup: () => ['1.0.0'],
      frozen: new Map(),
    })
    expect(blockers.map((b) => b.kind)).toEqual(['unsatisfiable-range'])
  })

  it('ignores devDependencies', () => {
    // A published tarball keeps its devDependencies in the manifest, but no
    // consumer installs them, so an unsatisfiable one breaks nothing. This is
    // why `packages/stack`'s `@cipherstash/eql: workspace:^` is not a finding
    // while `packages/cli`'s identical line is.
    expect(
      publishBlockers({
        manifests: [
          { name: EQL, version: '3.0.5', private: false, workspaceDeps: [] },
          {
            name: 'stack',
            version: '1.0.0',
            private: false,
            workspaceDeps: [
              { table: 'devDependencies', name: EQL, spec: 'workspace:^' },
            ],
          },
        ],
        lookup: (name) => (name === EQL ? ['3.0.4'] : ['1.0.0']),
        frozen: new Map(),
      }),
    ).toEqual([])
  })

  it('does not check a private package’s own dependencies', () => {
    // `examples/*`, `e2e` and `packages/bench` are never packed, so their
    // `workspace:*` lines reach no consumer.
    expect(
      publishBlockers({
        manifests: [
          {
            name: 'test-kit',
            version: '0.0.1',
            private: true,
            workspaceDeps: [],
          },
          {
            name: 'bench',
            version: '0.0.5',
            private: true,
            workspaceDeps: [
              { table: 'dependencies', name: 'test-kit', spec: 'workspace:*' },
            ],
          },
        ],
        lookup: empty,
        frozen: new Map(),
      }),
    ).toEqual([])
  })

  it('propagates a lookup error instead of reporting "nothing blocks"', () => {
    // The load-bearing direction, same as `unpublished`'s. A network, auth or
    // rate-limit failure must stop the gate — swallowed, it reads as "this
    // frozen package is already on npm", which is the one answer that lets the
    // broken release through.
    //
    // The manifest carries a FROZEN package deliberately: that is what makes
    // the registry answer load-bearing here. A package nothing asks about is
    // not looked up at all, and `[]` is then the right answer whatever the
    // registry is doing — so asserting the throw on that shape would pin an
    // eager round trip rather than the property.
    expect(() =>
      publishBlockers({
        manifests: [
          { name: EQL, version: '3.0.5', private: false, workspaceDeps: [] },
        ],
        lookup: () => {
          throw new Error('npm view failed: ETIMEDOUT')
        },
        frozen: new Map([[EQL, 'publisher not repointed yet']]),
      }),
    ).toThrow(/ETIMEDOUT/)
  })
})

describe('the gate over this repo’s real manifests', () => {
  // A SYNTHETIC REGISTRY over the REAL tree: every workspace package is
  // published at exactly the version the tree carries, EXCEPT `@cipherstash/eql`
  // — stuck at 3.0.4, which is npm's actual state. So the only thing this can
  // report is the consequence of the hand-applied 3.0.5 bump, and it reports it
  // from the manifests themselves rather than from a fixture that could drift
  // away from them.
  const manifests = workspaceManifests()
  const lookup = (name) => {
    if (name === EQL) return ['3.0.3', '3.0.4']
    const found = manifests.find((m) => m.name === name)
    return found ? [found.version] : null
  }
  const blockers = publishBlockers({ manifests, lookup })

  it('names the frozen package that cannot publish', () => {
    expect(
      blockers
        .filter((b) => b.kind === 'frozen-publisher')
        .map((b) => `${b.package}@${b.version}`),
    ).toEqual([`${EQL}@3.0.5`])
  })

  it('names every published package that would ship the unsatisfiable range', () => {
    // THE REGRESSION. `packages/cli` (`stash`) and `packages/stack-prisma` both
    // carry `"@cipherstash/eql": "workspace:^"` under `dependencies`, so both
    // pack `^3.0.5`. `packages/stack` carries the same line under
    // `devDependencies` and must NOT appear.
    expect(
      blockers
        .filter((b) => b.kind === 'frozen-dependency')
        .map((b) => `${b.package} -> ${b.dependency}@${b.range}`)
        .sort(),
    ).toEqual([
      `@cipherstash/stack-prisma -> ${EQL}@^3.0.5`,
      `stash -> ${EQL}@^3.0.5`,
    ])
  })

  it('reports nothing once the frozen package is on npm at its committed version', () => {
    // The exit condition, stated as a test: complete the Phase-5 repoint and
    // publish 3.0.5, and this gate goes quiet on its own. Nothing else has to
    // change — which is what makes the freeze a fact about the registry rather
    // than a policy encoded here.
    expect(
      publishBlockers({
        manifests,
        lookup: (name) => (name === EQL ? ['3.0.4', '3.0.5'] : lookup(name)),
      }),
    ).toEqual([])
  })
})

describe('the gate actually blocks the publish', () => {
  const workflow = readWorkflow('.github/workflows/release.yml')

  it('skips the release job unless the gate job succeeded', () => {
    // A gate that exits non-zero and stops nothing is a slower way of printing
    // a warning. `release` is the job that runs `changeset publish`, and its
    // condition is `always()` — needed, because `publish-ffi` is legitimately
    // skipped — so "gate failed" has to be excluded EXPLICITLY or `always()`
    // runs the publish straight through the failure.
    const release = workflow.jobs.release
    expect(release.needs).toContain('gate')
    expect(
      String(release.if),
      "release.yml's `release` job must require `needs.gate.result == 'success'`. Under " +
        '`always()` a failed gate would otherwise still reach `changeset publish`.',
    ).toMatch(/needs\.gate\.result\s*==\s*'success'/)
  })
})

/**
 * The gate as a PROCESS, driven against a fake registry.
 *
 * Every test above calls `publishBlockers` and reads what it returns. That
 * proves the analysis and nothing about the release: a `main()` that computed
 * the same list and exited 0 would pass all of them while publishing the broken
 * tarballs. The exit code is the entire mechanism — `release.yml`'s `release`
 * job is conditioned on `needs.gate.result == 'success'` — so it gets a test
 * that actually runs the script.
 *
 * `npm` is shimmed on PATH rather than the module being imported, because
 * `npmVersions` shells out to it. That also keeps this offline and
 * deterministic: the real registry would make the assertion below depend on
 * whether Phase 5 has happened yet.
 */
describe('the gate exits non-zero when a blocker is found', () => {
  const manifests = workspaceManifests()

  /** A PATH entry whose `npm view <name> versions --json` answers from `map`. */
  const fakeRegistry = (map) => {
    const dir = mkdtempSync(join(tmpdir(), 'release-gate-'))
    const versions = join(dir, 'versions.json')
    writeFileSync(versions, JSON.stringify(map))
    const shim = join(dir, 'npm')
    writeFileSync(
      shim,
      '#!/usr/bin/env node\n' +
        "const map = JSON.parse(require('node:fs').readFileSync(process.env.FAKE_NPM_VERSIONS, 'utf8'))\n" +
        'const found = map[process.argv[3]]\n' +
        "if (!found) { process.stderr.write('npm error code E404\\n'); process.exit(1) }\n" +
        'process.stdout.write(JSON.stringify(found))\n',
    )
    chmodSync(shim, 0o755)
    return { dir, versions }
  }

  /** Every workspace package published at exactly its committed version. */
  const allPublished = Object.fromEntries(
    manifests.map(({ name, version }) => [name, [version]]),
  )

  const runGate = (map) => {
    const { dir, versions } = fakeRegistry(map)
    const result = spawnSync(process.execPath, ['scripts/release-gate.mjs'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${dir}:${process.env.PATH}`,
        FAKE_NPM_VERSIONS: versions,
        // The real one would be written for the whole vitest run.
        GITHUB_OUTPUT: join(dir, 'github-output.txt'),
      },
    })
    rmSync(dir, { recursive: true, force: true })
    return result
  }

  it('fails the job, and says how to clear it', () => {
    // TODAY'S TREE against TODAY'S REGISTRY: @cipherstash/eql pinned to 3.0.4,
    // everything else current. Exit 1 is what skips the `release` job.
    const result = runGate({ ...allPublished, [EQL]: ['3.0.3', '3.0.4'] })
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('cannot be installed')
    expect(result.stderr).toContain(`${EQL}@3.0.5`)
    // The message has to name the way out, or a blocked release is a puzzle.
    expect(result.stderr).toContain('Phase 5')
  })

  it('still reports the publish set on the run it blocks', () => {
    // The `ffi`/`js` outputs are diagnostic and are written BEFORE the exit, so
    // the job log on a blocked run still says what was missing. Losing that
    // would make the blocked run less informative than a passing one.
    const result = runGate({ ...allPublished, [EQL]: ['3.0.3', '3.0.4'] })
    expect(result.stdout).toContain(`unpublished: ${EQL}`)
  })

  it('exits 0 once the frozen package is published', () => {
    // The other half of the mutation check: this must not be a gate that always
    // fails. Publish 3.0.5 and the same tree passes untouched.
    const result = runGate({ ...allPublished, [EQL]: ['3.0.4', '3.0.5'] })
    expect(result.stderr).toBe('')
    expect(result.status).toBe(0)
  })
})
