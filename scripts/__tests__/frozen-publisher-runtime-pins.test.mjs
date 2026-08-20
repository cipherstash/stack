import { describe, expect, it } from 'vitest'
import {
  FROZEN_PUBLISHERS,
  packedRange,
  workspaceManifests,
} from '../release-gate.mjs'

/**
 * A runtime dependency on a package published from ANOTHER repository must pack
 * to an EXACT version.
 *
 * ## The hole this closes
 *
 * `FROZEN_PUBLISHERS` in `scripts/release-gate.mjs` lists the packages that
 * live in this repo but are published from somewhere else. `@cipherstash/eql`
 * is the only one left — published from `cipherstash/encrypt-query-language`
 * until the Phase-5 cutover. (The seven protect-ffi packages were on that list
 * too, until their own cutover moved publishing here.) For the duration of such
 * a split, a version of the frozen package can appear on npm WITHOUT passing
 * through this repository at all.
 *
 * That is fine for a `workspace:` specifier as pnpm resolves it in the
 * workspace — it resolves in-tree, by definition. It is not fine for what pnpm
 * writes into the PACKED tarball, which is what a customer installs:
 *
 *     "@cipherstash/eql": "workspace:^"   packs as   "^3.0.5"
 *     "@cipherstash/eql": "workspace:*"   packs as   "3.0.5"
 *
 * The caret resolves any future 3.0.x published from the other repository,
 * while `@cipherstash/stack`'s v3 domain types and `@cipherstash/stack-prisma`'s
 * baked migrations stay frozen at whatever version this repo built against. That
 * is the emit/store skew `scripts/lint-no-eql-registry-pins.mjs` exists to
 * prevent, reintroduced one layer down — through the packed tarball rather than
 * through a manifest, so the linter reads the tree clean while the install
 * floats.
 *
 * `workspace:*` is the only specifier that satisfies both constraints at once:
 * the linter REQUIRES a `workspace:` prefix (a literal `"3.0.5"` is a registry
 * pin and exits 1), and `packedRange` makes `workspace:*` the exact version. So
 * the fix is a specifier, not a new verification step — and this test is what
 * stops the caret coming back.
 *
 * ## Why it asserts through `packedRange` rather than on the string
 *
 * The property is about what SHIPS, not about how the manifest is spelled.
 * Asserting `spec === 'workspace:*'` would pass a rewrite of `packedRange` that
 * quietly changed what `*` packs to, which is the one change that would make the
 * whole rule wrong. Driving the real function means the test fails when the
 * packing behaviour moves, not only when a manifest does.
 */

/**
 * The tables a CONSUMER of the packed tarball installs from.
 *
 * Mirrors `INSTALLED_TABLES` in `scripts/release-gate.mjs`, which is not
 * exported. `devDependencies` is deliberately absent for the same reason it is
 * absent there: pnpm rewrites the `workspace:` specifier in that table too and
 * the rewritten range does ship inside the packed `package.json`, but nothing
 * installing the package ever resolves it. The asymmetry is live in this tree —
 * `packages/stack` declares `@cipherstash/eql` under `devDependencies` and is
 * not a finding — so it is asserted below rather than left as an absence.
 */
const RUNTIME_TABLES = new Set([
  'dependencies',
  'optionalDependencies',
  'peerDependencies',
])

/** Every frozen-publisher `workspace:` declaration in the tree, as data. */
function frozenDeclarations() {
  const manifests = workspaceManifests()
  const byName = new Map(manifests.map((manifest) => [manifest.name, manifest]))
  return manifests.flatMap((manifest) =>
    (manifest.workspaceDeps ?? [])
      .filter((dep) => FROZEN_PUBLISHERS.has(dep.name))
      .map((dep) => {
        const target = byName.get(dep.name)
        return {
          consumer: manifest.name,
          consumerPrivate: manifest.private,
          table: dep.table,
          dependency: dep.name,
          spec: dep.spec,
          targetVersion: target?.version,
          packed: target ? packedRange(dep.spec, target.version) : null,
        }
      }),
  )
}

/** The id a finding is reported by — the string a reader has to go and find. */
const declarationId = (d) => `${d.consumer} [${d.table}] :: ${d.dependency}`

describe('frozen-publisher runtime pins', () => {
  it('packs every runtime frozen-publisher dependency as an exact version', () => {
    const loose = frozenDeclarations()
      .filter((d) => !d.consumerPrivate && RUNTIME_TABLES.has(d.table))
      .filter((d) => d.packed !== d.targetVersion)
      .map((d) => `${declarationId(d)} = ${d.spec} -> packs as ${d.packed}`)

    expect(loose).toEqual([])
  })

  it('sees the declarations it is supposed to be checking', () => {
    // A scan that stops matching exits green having checked nothing — the
    // failure mode `EXPECTED_DECLARERS` guards in the sibling linter. The floor
    // here is the same idea: a frozen publisher must still be reachable from a
    // published package's runtime tables, or the assertion above is vacuous.
    const runtime = frozenDeclarations().filter(
      (d) => !d.consumerPrivate && RUNTIME_TABLES.has(d.table),
    )
    expect(runtime.length).toBeGreaterThan(0)
    expect([...new Set(runtime.map((d) => d.dependency))].sort()).toContain(
      '@cipherstash/eql',
    )
  })

  it('does not fault a devDependency, which no consumer installs', () => {
    // `packages/stack` declares `@cipherstash/eql` under `devDependencies`. It
    // is the case that proves the narrowing above is a decision rather than an
    // oversight: if this ever appears in the finding list, RUNTIME_TABLES has
    // drifted from release-gate's INSTALLED_TABLES.
    const dev = frozenDeclarations().filter(
      (d) =>
        d.dependency === '@cipherstash/eql' && d.table === 'devDependencies',
    )
    expect(dev.map(declarationId)).toEqual([
      '@cipherstash/stack [devDependencies] :: @cipherstash/eql',
    ])
    expect(RUNTIME_TABLES.has('devDependencies')).toBe(false)
  })

  it('anchors the rule to what `workspace:*` and `workspace:^` actually pack', () => {
    // The whole fix rests on this asymmetry. Stated here so a change to
    // `packedRange` fails with the reason rather than with a manifest diff.
    expect(packedRange('workspace:*', '3.0.5')).toBe('3.0.5')
    expect(packedRange('workspace:^', '3.0.5')).toBe('^3.0.5')
    expect(packedRange('workspace:~', '3.0.5')).toBe('~3.0.5')
  })
})
