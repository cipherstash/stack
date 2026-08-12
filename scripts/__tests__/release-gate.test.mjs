import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import {
  classify,
  unpublished,
  workspacePackagePatterns,
} from '../release-gate.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

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
