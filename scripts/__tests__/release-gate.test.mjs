import { spawnSync } from 'node:child_process'
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import {
  classify,
  FROZEN_ARTEFACT_DIGESTS,
  FROZEN_PUBLISHERS,
  frozenBytesSkew,
  inTreeArtefactDigest,
  packedRange,
  publishBlockers,
  publishedArtefactDigest,
  reportBlockers,
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
 * That is not hypothetical here. `@cipherstash/eql` is published from
 * `cipherstash/encrypt-query-language`, so a version bumped in this workspace
 * cannot be published from this repository — while `packages/cli` and
 * `packages/stack-prisma` carry `"@cipherstash/eql": "workspace:*"` in their
 * RUNTIME dependencies, which pnpm rewrites to that exact version at pack time.
 * The hand-applied 3.0.5 bump put both of them a release ahead of the registry:
 * a range no published version satisfied, in a tarball that publishes fine.
 * Upstream released 3.0.5 afterwards and the gate went quiet on its own, which
 * is the property worth having — and the reason every fixture below carries its
 * own registry rather than asking the real one.
 *
 * Those two were `workspace:^` until the exact pin landed, and the change does
 * not weaken this check — it sharpens it. `^3.0.5` would have floated onto any
 * future 3.0.x published from the OTHER repository, which is the emit/store
 * skew the absorption exists to close;
 * `scripts/__tests__/frozen-publisher-runtime-pins.test.mjs` is what holds the
 * exact form. Here the only difference is the range string this gate reports.
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
    // The state a frozen package spends most of its life in, and the one the
    // retired `lint-no-ffi-changeset` guard rested on without saying so: while
    // the committed version is already on npm, `changeset publish` skips the
    // package entirely and the frozen publisher never matters. This is that
    // assumption, checked rather than assumed.
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

  it('blocks a private dependency even when its NAME resolves on npm', () => {
    // THE ORDERING. The registry-satisfaction check ran first and `continue`d,
    // so a private package whose name happens to resolve at a satisfying
    // version never reached the `private` test at all — and privacy is a
    // property of THIS tree, which no registry answer can revise. The doc
    // comment already said so ("a blocker either way, since no publish will
    // ever fix it"); the code disagreed.
    //
    // Reached the ordinary way: a package that was published, then marked
    // private. npm keeps every version it ever accepted, so the lookup goes on
    // answering long after the package stopped being publishable, and the
    // versions it answers with are unreachable from a workspace that no longer
    // packs it.
    const blockers = publishBlockers({
      manifests: [
        {
          name: 'test-kit',
          version: '2.3.4',
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
      // `workspace:*` packs as the exact `2.3.4`, which this registry satisfies.
      lookup: (name) => (name === 'test-kit' ? ['0.0.1', '2.3.4'] : ['1.0.0']),
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

/**
 * WHICH PACKAGES ARE STILL FROZEN — and, far more to the point, which are not.
 *
 * An entry that outlives its cutover does not fail loudly, it fails LATE. While
 * the package sits at a version already on npm the frozen check keeps passing,
 * so nothing notices; the FIRST bump after the publisher moves is then blocked
 * by a map that was describing the world as it used to be. The seven
 * protect-ffi entries reached exactly that state — written while the packages
 * published from `cipherstash/protectjs-ffi`, and left behind by the cutover
 * that repointed npm trusted publishing at this repository.
 *
 * So the map gets a test that names what is NOT in it. `FROZEN_PUBLISHERS.size
 * > 0` (asserted in `frozen-publisher-docs.test.mjs`) catches the map emptying
 * early; this catches it emptying late.
 */
describe('FROZEN_PUBLISHERS', () => {
  it('does not freeze the protect-ffi packages, whose publisher has moved here', () => {
    expect(
      [...FROZEN_PUBLISHERS.keys()].filter((name) => name.startsWith(FFI)),
      'npm trusted publishing for all seven protect-ffi packages is bound to ' +
        'this repository and `release.yml`. A frozen entry here blocks the ' +
        'first release that bumps one of them.',
    ).toEqual([])
  })

  it('does not block the first FFI release published from this repository', () => {
    // Driven through the REAL map, not a fixture: the defect is in the map's
    // contents, so a fixture would prove the mechanism and miss it entirely.
    // Every FFI version on the registry was published from the old repository,
    // so the first bump made here is by definition absent from npm — which is
    // what a release IS, and must not be read as a blocker.
    const blockers = publishBlockers({
      manifests: [
        { name: FFI, version: '0.32.0', private: false, workspaceDeps: [] },
        {
          name: PLATFORM,
          version: '0.32.0',
          private: false,
          workspaceDeps: [],
        },
        { name: EQL, version: '3.0.6', private: false, workspaceDeps: [] },
      ],
      lookup: (name) => (name === EQL ? ['3.0.5'] : ['0.31.0']),
    })
    expect(blockers.map((blocker) => blocker.package)).toEqual([EQL])
  })
})

/**
 * THE MESSAGE IS THE ENTIRE PRODUCT OF A FAILING GATE, so the way out has to
 * describe the findings in front of the reader rather than the ones in front of
 * whoever wrote it. The text named `3.0.5` outright — correct on the day, stale
 * by the next release, and LATENT either way, because `reportBlockers` runs
 * only when there is something to block. A wrong instruction that prints once a
 * quarter is a wrong instruction nobody is watching.
 */
describe('reportBlockers', () => {
  /** The "two ways past this" tail — the part that tells you what to do. */
  const remedy = (message) =>
    message.slice(message.indexOf('There are exactly two ways past this'))

  it('takes the version to publish from the findings', () => {
    const message = reportBlockers([
      {
        kind: 'frozen-publisher',
        package: EQL,
        version: '4.1.0',
        reason: 'publisher not repointed yet',
      },
    ])
    expect(remedy(message)).toContain(`${EQL}@4.1.0`)
    expect(
      remedy(message),
      'the way out must name the version actually blocked, not one written into ' +
        'the message when it was drafted.',
    ).not.toMatch(/3\.0\.5/)
  })

  it('names no version at all when no frozen package is among the findings', () => {
    // A private dependency is not fixed by publishing anything, so a sentence
    // telling the reader to publish some version is worse than silence.
    const message = reportBlockers([
      {
        kind: 'private-dependency',
        package: 'stash',
        dependency: 'test-kit',
        table: 'dependencies',
        range: '0.0.1',
      },
    ])
    expect(remedy(message)).not.toMatch(/\d+\.\d+\.\d+/)
  })
})

describe('the gate over this repo’s real manifests', () => {
  // A SYNTHETIC REGISTRY over the REAL tree: every workspace package is
  // published at exactly the version the tree carries, EXCEPT `@cipherstash/eql`
  // — held one release behind, the state npm was in while the hand-applied
  // 3.0.5 bump sat unpublished. So the only thing this can report is the
  // consequence of that bump, and it reports it from the manifests themselves
  // rather than from a fixture that could drift away from them. Synthetic on
  // purpose: these assertions must not move when the registry does.
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
    // carry `"@cipherstash/eql": "workspace:*"` under `dependencies`, so both
    // pack the exact `3.0.5`. `packages/stack` carries the same line under
    // `devDependencies` and must NOT appear.
    expect(
      blockers
        .filter((b) => b.kind === 'frozen-dependency')
        .map((b) => `${b.package} -> ${b.dependency}@${b.range}`)
        .sort(),
    ).toEqual([
      `@cipherstash/stack-prisma -> ${EQL}@3.0.5`,
      `stash -> ${EQL}@3.0.5`,
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
 *
 * THE SHIM ANSWERS `pack` AS WELL AS `view`, and that is not tidying. It used
 * to answer `view` only, so `publishedArtefactDigest`'s `npm pack` got a
 * synthetic `E404`, returned `null`, and CHECK C compared nothing on every run
 * of this suite — the gate's only registry-versus-tree check, exercised
 * end-to-end by nothing. Now the shim builds a real tarball with the published
 * layout, so `main()` runs the extraction and the comparison for real.
 */
describe('the gate exits non-zero when a blocker is found', () => {
  const manifests = workspaceManifests()

  /** The digest the tree currently claims for the frozen package's install SQL. */
  const IN_TREE_DIGEST = inTreeArtefactDigest(
    EQL,
    FROZEN_ARTEFACT_DIGESTS.get(EQL),
  )

  /**
   * A PATH entry whose `npm view <name> versions --json` answers from `map`,
   * and whose `npm pack <spec>` produces a tarball carrying `packDigest`.
   */
  const fakeRegistry = (map, packDigest) => {
    const dir = mkdtempSync(join(tmpdir(), 'release-gate-'))
    const versions = join(dir, 'versions.json')
    writeFileSync(versions, JSON.stringify(map))
    const shim = join(dir, 'npm')
    writeFileSync(
      shim,
      '#!/usr/bin/env node\n' +
        "const fs = require('node:fs'), path = require('node:path')\n" +
        "const map = JSON.parse(fs.readFileSync(process.env.FAKE_NPM_VERSIONS, 'utf8'))\n" +
        "if (process.argv[2] === 'pack') {\n" +
        // `name@version`, split on the LAST `@` so the scope survives.
        '  const spec = process.argv[3]\n' +
        "  const at = spec.lastIndexOf('@')\n" +
        '  const [name, version] = [spec.slice(0, at), spec.slice(at + 1)]\n' +
        '  if (!(map[name] ?? []).includes(version)) {\n' +
        "    process.stderr.write('npm error code ETARGET\\n'); process.exit(1)\n" +
        '  }\n' +
        "  const dest = process.argv[process.argv.indexOf('--pack-destination') + 1]\n" +
        "  const stage = path.join(dest, 'stage', 'package', 'dist', 'sql')\n" +
        '  fs.mkdirSync(stage, { recursive: true })\n' +
        "  fs.writeFileSync(path.join(stage, 'release-manifest.json'), JSON.stringify({\n" +
        '    eqlVersion: version, schemaVersion: 3,\n' +
        '    installSqlSha256: process.env.FAKE_NPM_PACK_DIGEST,\n' +
        "    uninstallSqlSha256: 'unused',\n" +
        '  }))\n' +
        "  require('node:child_process').execFileSync('tar', ['-czf', path.join(dest, 'f.tgz'), '-C', path.join(dest, 'stage'), '.'])\n" +
        "  process.stdout.write('f.tgz\\n'); process.exit(0)\n" +
        '}\n' +
        'const found = map[process.argv[3]]\n' +
        "if (!found) { process.stderr.write('npm error code E404\\n'); process.exit(1) }\n" +
        'process.stdout.write(JSON.stringify(found))\n',
    )
    chmodSync(shim, 0o755)
    return { dir, versions, packDigest }
  }

  /** Every workspace package published at exactly its committed version. */
  const allPublished = Object.fromEntries(
    manifests.map(({ name, version }) => [name, [version]]),
  )

  const runGate = (map, packDigest = IN_TREE_DIGEST) => {
    const { dir, versions } = fakeRegistry(map, packDigest)
    const result = spawnSync(process.execPath, ['scripts/release-gate.mjs'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${dir}:${process.env.PATH}`,
        FAKE_NPM_VERSIONS: versions,
        FAKE_NPM_PACK_DIGEST: packDigest,
        // The real one would be written for the whole vitest run.
        GITHUB_OUTPUT: join(dir, 'github-output.txt'),
      },
    })
    rmSync(dir, { recursive: true, force: true })
    return result
  }

  it('fails the job, and says how to clear it', () => {
    // THE REAL TREE against a registry held one release behind it:
    // @cipherstash/eql pinned to 3.0.4, everything else at its committed
    // version. Exit 1 is what skips the `release` job.
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
    // fails. Publish 3.0.5 and the same tree passes untouched — and now the
    // tarball this run downloads carries the tree's own digest, so CHECK C is
    // genuinely compared rather than skipped for want of a tarball.
    const result = runGate({ ...allPublished, [EQL]: ['3.0.4', '3.0.5'] })
    expect(result.stderr).toBe('')
    expect(result.status).toBe(0)
  })

  it('blocks the release when npm’s bytes are not the tree’s bytes', () => {
    // CHECK C, end to end, through `main()`. The registry carries 3.0.5 — so
    // `publishBlockers` finds nothing — and the tarball for it hashes something
    // else, which is exactly the #885 defect: `packages/eql` at 3.0.5 with an
    // install bundle npm's 3.0.5 does not contain. `stash eql install` reads
    // that SQL verbatim, with no digest check of its own.
    const result = runGate(
      { ...allPublished, [EQL]: ['3.0.4', '3.0.5'] },
      '7ad9c9f8beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef',
    )
    expect(result.status).toBe(1)
    expect(result.stderr).toContain('is NOT the 3.0.5 that is on npm')
    expect(result.stderr).toContain(IN_TREE_DIGEST)
    expect(result.stderr).toContain('7ad9c9f8beef')
    // Publishing cannot clear this one, and saying so is the whole point of
    // the separate remedy branch.
    expect(result.stderr).not.toMatch(/Publish the frozen package\./)
  })

  it('does not crash on a frozen version npm has never carried', () => {
    // The ETARGET path, through the process. Before the fix this was an
    // uncaught throw with an EMPTY reason (`npm pack …@3.0.5 failed:`), raised
    // while building the blocker array — so `reportBlockers` never ran and the
    // operator got a stack trace instead of the frozen-publisher remedy that
    // was already computed. Still exit 1; now for a legible reason.
    const result = runGate({ ...allPublished, [EQL]: ['3.0.4'] })
    expect(result.status).toBe(1)
    expect(result.stderr).not.toMatch(/npm pack .* failed:\s*$/m)
    expect(result.stderr).toContain('Phase 5')
  })
})

describe('frozenBytesSkew', () => {
  /**
   * THE FAILURE THIS EXISTS FOR, and it is not hypothetical — it is what the
   * #885 review found by hand on a branch nothing in CI would have stopped.
   *
   * A frozen package cannot be published from this repository, so its in-tree
   * bytes are not a candidate for release: they are a CLAIM about a version
   * that already exists elsewhere. Break the claim and every consumer of the
   * workspace build runs an artefact no release corresponds to, while every
   * digest in the tree still verifies — the manifest is regenerated alongside
   * the SQL, so it agrees with whatever was generated. Only the registry
   * disagrees, and nothing was asking it.
   *
   * Concretely: `packages/eql` sat at `3.0.5` with an install bundle whose
   * sha256 was `7ad9c9f8…`, while `@cipherstash/eql@3.0.5` on npm was
   * `accde0030…` (upstream had restored the deprecated `ste_vec_contains`
   * aliases). `stash eql install` reads that SQL verbatim, so a customer
   * database would carry functions that the version it reports does not
   * define.
   */
  const EQL_305 = { name: EQL, version: '3.0.5', private: false }

  it('is silent when the in-tree artefact matches the published one', () => {
    expect(
      frozenBytesSkew({
        manifests: [EQL_305],
        frozen: new Map([[EQL, 'publisher not repointed yet']]),
        artefacts: new Map([[EQL, { label: 'install SQL' }]]),
        inTreeDigest: () => 'accde0030',
        publishedDigest: () => 'accde0030',
      }),
    ).toEqual([])
  })

  it('blocks when the in-tree artefact differs from the published one', () => {
    const blockers = frozenBytesSkew({
      manifests: [EQL_305],
      frozen: new Map([[EQL, 'publisher not repointed yet']]),
      artefacts: new Map([[EQL, { label: 'install SQL' }]]),
      inTreeDigest: () => '7ad9c9f8',
      publishedDigest: () => 'accde0030',
    })
    expect(blockers).toEqual([
      {
        kind: 'frozen-bytes-skew',
        package: EQL,
        version: '3.0.5',
        label: 'install SQL',
        local: '7ad9c9f8',
        published: 'accde0030',
      },
    ])
  })

  it('says nothing about a package this repository CAN publish', () => {
    // A non-frozen package's in-tree bytes are the release. Differing from
    // what is on npm is the normal state of an unreleased change, not a
    // finding — and treating it as one would block every ordinary PR.
    expect(
      frozenBytesSkew({
        manifests: [{ name: FFI, version: '0.33.0', private: false }],
        frozen: new Map([[EQL, 'publisher not repointed yet']]),
        artefacts: new Map([[EQL, { label: 'install SQL' }]]),
        inTreeDigest: () => 'aaaa',
        publishedDigest: () => 'bbbb',
      }),
    ).toEqual([])
  })

  it('defers to the frozen-publisher blocker when the version is absent from npm', () => {
    // `publishedDigest` returns null for a version npm does not carry. There
    // is nothing to compare against, and `publishBlockers` already reports
    // that exact case as `frozen-publisher` — two blockers for one fact would
    // make the remediation ambiguous.
    expect(
      frozenBytesSkew({
        manifests: [{ ...EQL_305, version: '3.0.6' }],
        frozen: new Map([[EQL, 'publisher not repointed yet']]),
        artefacts: new Map([[EQL, { label: 'install SQL' }]]),
        inTreeDigest: () => '7ad9c9f8',
        publishedDigest: () => null,
      }),
    ).toEqual([])
  })

  it('throws when a frozen publisher has no artefact declared', () => {
    // The stale-configuration case, loud rather than silent. A frozen package
    // with nothing to compare passes this check by having no check — the same
    // shape as an exemption excusing nothing, which the sibling EQL-pin linter
    // exits 2 on.
    expect(() =>
      frozenBytesSkew({
        manifests: [EQL_305],
        frozen: new Map([[EQL, 'publisher not repointed yet']]),
        artefacts: new Map(),
        inTreeDigest: () => 'x',
        publishedDigest: () => 'x',
      }),
    ).toThrow(/artefact/i)
  })

  it('every frozen publisher in the real map declares an artefact', () => {
    // The two maps are edited in different PRs by different people. Keyed
    // equality is what stops a frozen publisher arriving with no bytes check
    // and reading like one that passed.
    expect([...FROZEN_ARTEFACT_DIGESTS.keys()].sort()).toEqual(
      [...FROZEN_PUBLISHERS.keys()].sort(),
    )
  })
})

/**
 * CHECK C's actual implementation, which no test was reaching.
 *
 * Every `frozenBytesSkew` test above INJECTS both digests, and the end-to-end
 * process test shims `npm` with a script that answers `npm view` and nothing
 * else — so `npm pack` hit that shim, got a synthetic `E404`, and
 * `publishedArtefactDigest` returned `null`, which `frozenBytesSkew` reads as
 * "nothing to compare". The `npm pack` + `tar` path, the one that actually
 * decides whether a release is blocked, executed in no test at all.
 *
 * What that concealed, found the moment the path was driven for real:
 *
 *   * `--silent` sets npm's loglevel to silent, so a FAILED `npm pack` wrote
 *     nothing to stderr. The `text.includes('E404')` classification therefore
 *     never matched, and the documented `null` return was unreachable;
 *   * npm answers a missing VERSION of an existing package with `ETARGET`
 *     (`No matching version found for …`), not `E404` — which is what
 *     `@cipherstash/eql@<next>` will be on every release before upstream
 *     publishes it. `E404` alone is the wrong code for the one case this
 *     function documents.
 *
 * Together those turned "npm does not carry that version" into an uncaught
 * throw with an EMPTY reason — `npm pack @cipherstash/eql@3.0.6 failed:` and a
 * stack trace — thrown while building the blocker array, so `reportBlockers`
 * never ran and the actionable `frozen-publisher` message was never printed.
 * Fail-closed, and unreadable.
 *
 * These drive the real function against a shimmed `npm` that produces a REAL
 * tarball, so `tar` genuinely extracts and the JSON is genuinely parsed.
 */
describe('publishedArtefactDigest, against a real tarball', () => {
  const ARTEFACT = {
    label: 'install SQL',
    inTree: 'packages/eql/packages/eql/sql/release-manifest.json',
    published: 'package/dist/sql/release-manifest.json',
    field: 'installSqlSha256',
  }

  /**
   * A PATH entry whose `npm pack` behaves like `behaviour` says.
   *
   * `tar` is deliberately NOT shimmed: the point is to run the real one over a
   * real gzipped tarball, so a change to the published layout fails here rather
   * than at release time.
   */
  const fakeNpm = (behaviour) => {
    const dir = mkdtempSync(join(tmpdir(), 'release-gate-pack-'))
    const marker = join(dir, 'invoked.txt')
    const script = join(dir, 'behaviour.js')
    writeFileSync(script, behaviour)
    const shim = join(dir, 'npm')
    writeFileSync(
      shim,
      '#!/usr/bin/env node\n' +
        "require('node:fs').appendFileSync(process.env.PACK_MARKER, process.argv.slice(2).join(' ') + '\\n')\n" +
        'require(process.env.PACK_BEHAVIOUR)(process.argv.slice(2))\n',
    )
    chmodSync(shim, 0o755)
    return { dir, marker, script }
  }

  /**
   * Build `<name>-<version>.tgz` whose contents are `files` (tarball-relative
   * paths), and answer `npm pack` with it.
   */
  const packing = (files) => `
const { execFileSync } = require('node:child_process')
const { mkdirSync, writeFileSync } = require('node:fs')
const { dirname, join } = require('node:path')
module.exports = (argv) => {
  const dest = argv[argv.indexOf('--pack-destination') + 1]
  const stage = join(dest, 'stage')
  for (const [path, body] of Object.entries(${JSON.stringify(files)})) {
    mkdirSync(dirname(join(stage, path)), { recursive: true })
    writeFileSync(join(stage, path), body)
  }
  execFileSync('tar', ['-czf', join(dest, 'fixture.tgz'), '-C', stage, '.'])
  process.stdout.write('fixture.tgz\\n')
}
`

  /**
   * Run `publishedArtefactDigest` with `npm` shimmed onto PATH, and report
   * both what it returned and the argv the shim was actually handed.
   *
   * PATH is mutated in-process rather than the executor being injected: the
   * production code resolves `npm` through `execFileSync`, and injecting a
   * runner would prove a different function. `scripts/vitest.config.mjs` sets
   * `fileParallelism: false`, so no sibling suite observes the window.
   */
  const withShim = (behaviour, fn) => {
    const { dir, marker, script } = fakeNpm(behaviour)
    const path = process.env.PATH
    process.env.PATH = `${dir}:${path}`
    process.env.PACK_MARKER = marker
    process.env.PACK_BEHAVIOUR = script
    try {
      return { value: fn(), argv: readFileSync(marker, 'utf8') }
    } finally {
      process.env.PATH = path
      rmSync(dir, { recursive: true, force: true })
    }
  }

  const MANIFEST = JSON.stringify({
    eqlVersion: '3.0.5',
    schemaVersion: 3,
    installSqlSha256: 'accde0030',
    uninstallSqlSha256: 'b1b5131b',
  })

  it('reads the digest out of the published tarball', () => {
    // The whole path, for real: `npm pack` produces a gzipped tarball, `tar`
    // extracts the one manifest path out of it, and the field is parsed.
    const { value, argv } = withShim(
      packing({
        'package/package.json': '{"name":"@cipherstash/eql"}',
        'package/dist/sql/release-manifest.json': MANIFEST,
      }),
      () => publishedArtefactDigest('@cipherstash/eql', '3.0.5', ARTEFACT),
    )
    expect(value).toBe('accde0030')
    // The floor. A shim that is never reached would let a hardcoded return
    // value pass this — and PATH resolution inside `execFileSync` is exactly
    // the kind of thing that silently stops working.
    expect(argv).toMatch(/pack @cipherstash\/eql@3\.0\.5/)
  })

  it('names the missing path when the tarball layout has changed', () => {
    // A published layout that moves `sql/` makes `tar` exit non-zero. It
    // already failed closed — the `tar` call is outside the E404 catch — but
    // the thrown message was `Command failed: tar -xzf …` with tar's own
    // stderr piped away, which is a release blocked by a puzzle.
    expect(() =>
      withShim(
        packing({
          'package/package.json': '{"name":"@cipherstash/eql"}',
          'package/sql/release-manifest.json': MANIFEST,
        }),
        () => publishedArtefactDigest('@cipherstash/eql', '3.0.5', ARTEFACT),
      ),
    ).toThrow(
      /could not extract `package\/dist\/sql\/release-manifest\.json`[\s\S]*layout has changed/,
    )
  })

  it('throws rather than returning undefined when the field is gone', () => {
    // `frozenBytesSkew` treats `undefined` as "nothing to compare" and moves
    // on, so a manifest that stopped carrying `installSqlSha256` would disarm
    // CHECK C while every test above stayed green. Stale configuration must
    // not read as a verdict — the rule the sibling EQL-pin linter exits 2 on.
    expect(() =>
      withShim(
        packing({
          'package/dist/sql/release-manifest.json': JSON.stringify({
            eqlVersion: '3.0.5',
          }),
        }),
        () => publishedArtefactDigest('@cipherstash/eql', '3.0.5', ARTEFACT),
      ),
    ).toThrow(/installSqlSha256/)
  })

  /** An `npm pack` that fails with `code` on stderr, the way npm does. */
  const failing = (code) => `
module.exports = () => {
  process.stderr.write('npm error code ${code}\\n')
  process.stderr.write('npm error ${code} No matching version found.\\n')
  process.exit(1)
}
`

  it('returns null for a version npm does not carry', () => {
    // ETARGET, not E404 — npm's answer when the PACKAGE exists and the version
    // does not, which is every EQL bump before upstream publishes it. Verified
    // against the real registry: `npm pack @cipherstash/eql@9.9.9` prints
    // `npm error code ETARGET`.
    expect(
      withShim(failing('ETARGET'), () =>
        publishedArtefactDigest('@cipherstash/eql', '9.9.9', ARTEFACT),
      ).value,
    ).toBeNull()
  })

  it('returns null for a package npm has never carried', () => {
    expect(
      withShim(failing('E404'), () =>
        publishedArtefactDigest('@cipherstash/nope', '1.0.0', ARTEFACT),
      ).value,
    ).toBeNull()
  })

  it('throws on any other failure rather than reading it as "nothing to compare"', () => {
    // The load-bearing direction, same as every other lookup in this script. A
    // network or auth failure swallowed here disarms CHECK C for that run.
    expect(() =>
      withShim(failing('ETIMEDOUT'), () =>
        publishedArtefactDigest('@cipherstash/eql', '3.0.5', ARTEFACT),
      ),
    ).toThrow(/ETIMEDOUT/)
  })

  it('does not pass --silent, which suppresses the code it classifies on', () => {
    // The defect, stated over the argv the shim recorded. `--silent` sets npm's
    // loglevel to silent: the pack still fails, but with EMPTY stderr, so the
    // classification below it can never match and the documented `null` return
    // is unreachable. Verified by hand against the real npm before the fix.
    const { argv } = withShim(
      packing({ 'package/dist/sql/release-manifest.json': MANIFEST }),
      () => publishedArtefactDigest('@cipherstash/eql', '3.0.5', ARTEFACT),
    )
    expect(argv).not.toContain('--silent')
  })
})

describe('inTreeArtefactDigest, over the real committed manifest', () => {
  it('reads the digest the tree claims for the frozen package', () => {
    // Driven through the REAL map and the REAL file: this is the side of the
    // comparison that lives in this repository, so a path that stops resolving
    // is a check that stops checking.
    const artefact = FROZEN_ARTEFACT_DIGESTS.get('@cipherstash/eql')
    expect(artefact).toBeDefined()
    expect(inTreeArtefactDigest('@cipherstash/eql', artefact)).toMatch(
      /^[0-9a-f]{64}$/,
    )
  })

  it('throws when the declared field is not in the manifest', () => {
    // The same stale-configuration rule as the published side. `frozenBytesSkew`
    // compares `local !== published`, so an `undefined` local against a real
    // published digest would report a skew with `local: undefined` — a blocked
    // release describing the wrong defect.
    //
    // The fixture lives outside the repo and is addressed by a relative path,
    // because `inTreeArtefactDigest` resolves against REPO_ROOT and four other
    // agents are working in this tree.
    const dir = mkdtempSync(join(tmpdir(), 'release-gate-intree-'))
    try {
      const file = join(dir, 'release-manifest.json')
      writeFileSync(file, JSON.stringify({ eqlVersion: '3.0.5' }))
      expect(() =>
        inTreeArtefactDigest('@cipherstash/eql', {
          inTree: relative(REPO_ROOT, file),
          field: 'installSqlSha256',
        }),
      ).toThrow(/installSqlSha256/)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})

describe('reportBlockers, for a bytes skew', () => {
  it('names both digests and does not offer "publish it" as a way out', () => {
    // Publishing cannot fix this one — the version is already on npm, and it
    // is not this repository's to republish. The only resolutions are to make
    // the tree match or to bump, so the message must not repeat the
    // frozen-publisher remedy.
    const text = reportBlockers([
      {
        kind: 'frozen-bytes-skew',
        package: EQL,
        version: '3.0.5',
        label: 'install SQL',
        local: '7ad9c9f8',
        published: 'accde0030',
      },
    ])
    expect(text).toContain('7ad9c9f8')
    expect(text).toContain('accde0030')
    expect(text).toContain('install SQL')
    expect(text).not.toMatch(/Publish the frozen package\./)
  })
})
