/**
 * Drift guard: the example app's vendored cipherstash contract space
 * (`examples/prisma/migrations/cipherstash/`) must be byte-identical to
 * the artefacts this package ships.
 *
 * The CLI's seed phase copies the descriptor's migration packages into a
 * consumer repo only when missing — existing directories are never
 * refreshed — so a vendored copy that drifts from the package wedges
 * every subsequent `migration plan` with PN-MIG-5002. The example is our
 * in-repo consumer: this test makes that drift (or a stale leftover
 * directory from an earlier package version) a CI failure instead of a
 * latent breakage discovered by the next person to run `plan`.
 *
 * Byte-parity is the design's core property (see
 * `src/migration/eql-bundle-v3.ts`): the SQL is baked and digest-pinned
 * at emit, the descriptor wires artefacts verbatim, and the seed phase
 * therefore materialises copies identical to this package's committed
 * files. If this test fails after intentionally changing the package's
 * migrations, regenerate the example's copy:
 *
 *   cd examples/prisma && rm -rf migrations/cipherstash \
 *     && pnpm exec prisma-next migration plan --name sync   # then delete
 *                                                          # the planned
 *                                                          # app-space dir
 *
 * (or simply copy the package's `migration.json` / `ops.json` pairs —
 * byte-parity makes plain `cp` a correct sync).
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const here = dirname(fileURLToPath(import.meta.url))
const packageRoot = join(here, '..', '..')
const packageMigrationsDir = join(packageRoot, 'migrations')
const vendoredDir = join(
  packageRoot,
  '..',
  '..',
  'examples',
  'prisma',
  'migrations',
  'cipherstash',
)

function migrationDirNames(root: string): string[] {
  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name !== 'refs')
    .map((entry) => entry.name)
    .sort()
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'))
}

describe('example vendored cipherstash space parity', () => {
  it('the example vendors exactly the migration set this package ships — no extras, no gaps', () => {
    expect(existsSync(vendoredDir)).toBe(true)
    // An extra vendored directory is a stale leftover from an earlier
    // package version (the class that wedged the example before the
    // baked-artefact design); a missing one means the seed phase has not
    // been re-run after adding a migration here.
    expect(migrationDirNames(vendoredDir)).toEqual(
      migrationDirNames(packageMigrationsDir),
    )
  })

  it('every vendored migration package is byte-identical to the shipped artefact', () => {
    for (const dirName of migrationDirNames(packageMigrationsDir)) {
      for (const file of ['migration.json', 'ops.json']) {
        const shipped = readFileSync(
          join(packageMigrationsDir, dirName, file),
          'utf8',
        )
        const vendored = readFileSync(join(vendoredDir, dirName, file), 'utf8')
        expect(vendored, `${dirName}/${file}`).toBe(shipped)
      }
    }
  })

  it('the vendored head ref and contract agree with the shipped artefacts', () => {
    // head.json / contract.json are re-serialised through canonicalizeJson
    // by the seed phase, so compare parsed content rather than bytes.
    const shippedHead = readJson(
      join(packageMigrationsDir, 'refs', 'head.json'),
    ) as { hash: string; invariants: string[] }
    const vendoredHead = readJson(join(vendoredDir, 'refs', 'head.json')) as {
      hash: string
      invariants: string[]
    }
    expect(vendoredHead.hash).toBe(shippedHead.hash)
    expect([...vendoredHead.invariants].sort()).toEqual(
      [...shippedHead.invariants].sort(),
    )

    const shippedContract = readJson(join(packageRoot, 'src', 'contract.json'))
    const vendoredContract = readJson(join(vendoredDir, 'contract.json'))
    expect(vendoredContract).toEqual(shippedContract)
  })
})
