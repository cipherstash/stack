/**
 * What happens to a consumer who IGNORES the 3.0.5 changeset's "Action
 * required" note — i.e. keeps a `migrations/cipherstash/` directory
 * generated against `@cipherstash/stack-prisma@1.0.0` and upgrades the
 * package underneath it.
 *
 * The 3.0.5 release re-emitted the published baseline
 * (`20260601T0100_install_eql_v3_bundle`): its bytes, and so its
 * `migrationHash`, changed from `sha256:fc495f7f…` to `sha256:23c98b03…`.
 * These artefacts are content-addressed and normally append-only, so a
 * re-emit is the one case the machinery was never designed for. The
 * changeset tells consumers to delete the vendored directory and re-run
 * `prisma-next migration plan`. That instruction is prose in a changelog:
 * this suite pins what actually happens when it is not followed.
 *
 * The mechanism, established by reading the framework (no live database
 * is involved in any of it):
 *
 *   - `migrationHash` is computed over a package's OWN bytes
 *     (`verifyMigrationHash`), so a stale-but-intact vendored baseline is
 *     SELF-CONSISTENT and passes every integrity check. Nothing anywhere
 *     compares an on-disk package against the descriptor's shipped one.
 *   - The CLI seed phase (`migration plan`) materialises descriptor
 *     packages with `materialiseExtensionMigrationPackageIfMissing` — a
 *     by-existence skip. The stale baseline is silently retained; only the
 *     new 3.0.5 directory is written. `refs/head.json` IS overwritten.
 *   - `db init` / `db update` / `migrate` then plan from the ON-DISK
 *     graph only (`computeExtensionSpaceApplyPath`); the descriptor is
 *     never consulted again.
 *
 * The suite is offline and deterministic — the fixture is reconstructed
 * from artefacts already in this repo and proved byte-equivalent to the
 * published 1.0.0 baseline by its content hash (see
 * `STALE_1_0_0_BASELINE_HASH`). It therefore runs in the normal
 * `pnpm --filter @cipherstash/stack-prisma test` suite with no env guard
 * and no skip.
 */
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { MigrationPlanOperation } from '@prisma-next/framework-components/control'
import { computeMigrationHash } from '@prisma-next/migration-tools/hash'
import {
  materialiseExtensionMigrationPackageIfMissing,
  readMigrationsDir,
  writeMigrationPackage,
} from '@prisma-next/migration-tools/io'
import type { MigrationMetadata } from '@prisma-next/migration-tools/metadata'
import type { MigrationOps } from '@prisma-next/migration-tools/package'
import {
  computeExtensionSpaceApplyPath,
  emitContractSpaceArtefacts,
  spaceMigrationDirectory,
} from '@prisma-next/migration-tools/spaces'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import v3BaselineMetadata from '../../migrations/20260601T0100_install_eql_v3_bundle/migration.json' with {
  type: 'json',
}
import headRef from '../../migrations/refs/head.json' with { type: 'json' }
import cipherstashDescriptor from '../../src/exports/control'
import { CIPHERSTASH_SPACE_ID } from '../../src/extension-metadata/constants'
import {
  CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_305_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_INVARIANTS,
} from '../../src/extension-metadata/constants-v3'

/**
 * The `migrationHash` `@cipherstash/stack-prisma@1.0.0` published for
 * `20260601T0100_install_eql_v3_bundle`, before the 3.0.5 re-emit. It is
 * what a consumer's vendored copy still carries. Recorded here as the
 * fixture's acceptance criterion, not as live history: the frozen set of
 * CURRENT hashes lives in `migration-v3.test.ts`.
 */
const STALE_1_0_0_BASELINE_HASH =
  'sha256:fc495f7f59e6d18ae8e3df594a38898263ca91f8f5fb5f625bff20d04a0d7223'

/** The three invariants a 1.0.0 install recorded on the marker row. */
const INVARIANTS_1_0_0 = [
  CIPHERSTASH_V3_INVARIANTS.installBundle,
  CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
  CIPHERSTASH_V3_INVARIANTS.upgradeBundle304,
] as const

/**
 * The runner's apply-time policy gate, reproduced. `db init` runs with
 * `allowedOperationClasses: ['additive']`; the Postgres target's
 * `enforcePolicyCompatibility` refuses the whole run on the first op
 * outside that set, naming only the operation id and its class.
 * (`migrate` and `db update` allow more classes — `migrate` allows all
 * four, which is why the same on-disk state behaves differently there.)
 */
function opsRefusedByDbInitPolicy(
  ops: ReadonlyArray<{ readonly id: string; readonly operationClass: string }>,
): readonly string[] {
  return ops.filter((op) => op.operationClass !== 'additive').map((op) => op.id)
}

/**
 * The SQL target's op shape. `MigrationPlanOperation` (the framework's
 * base type) carries only `id` / `label` / `operationClass` /
 * `invariantId`; the `execute` / `postcheck` step lists are added by
 * `@prisma-next/target-postgres` and are what this suite reads. Declared
 * locally so the single widening cast lives in `asSqlOps` below rather
 * than at every use site.
 */
interface SqlMigrationOp extends MigrationPlanOperation {
  readonly execute: ReadonlyArray<{
    readonly description: string
    readonly sql: string
  }>
  readonly postcheck: ReadonlyArray<{
    readonly description: string
    readonly sql: string
  }>
}

function asSqlOps(ops: MigrationOps): readonly SqlMigrationOp[] {
  return ops as readonly SqlMigrationOp[]
}

function descriptorSpace() {
  const space = cipherstashDescriptor.contractSpace
  if (!space) throw new Error('descriptor ships no contractSpace')
  return space
}

function descriptorPackage(dirName: string) {
  const pkg = descriptorSpace().migrations.find((m) => m.dirName === dirName)
  if (!pkg) throw new Error(`descriptor is missing ${dirName}`)
  return pkg
}

/**
 * Rebuild the 1.0.0 baseline package from artefacts still in this repo.
 *
 * Every byte is recoverable without a fixture blob: the 1.0.0 baseline's
 * install SQL is the same eql-3.0.4 bundle the `20260728T0000` upgrade
 * edge bakes (both pin `installSqlSha256` `63104a81…` — see
 * `migration-v3.test.ts`), and the surrounding op shape differs from
 * today's baseline only in the release string and the missing 3.0.5
 * carrier op. The reconstruction is *proved* faithful by hashing it: the
 * `migrationHash` test below demands `sha256:fc495f7f…`, the value 1.0.0
 * published. Content addressing makes that an exact-bytes assertion, so
 * this fixture cannot silently drift into "some old-looking baseline".
 */
function buildStale100Baseline(): {
  readonly metadata: MigrationMetadata
  readonly ops: readonly SqlMigrationOp[]
} {
  const to304 = (text: string): string => text.replaceAll('3.0.5', '3.0.4')
  const shipped = asSqlOps(
    descriptorPackage(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME).ops,
  )
  const install = shipped[0]
  const carrier302 = shipped[1]
  const carrier304 = shipped[2]
  const bundle304 = asSqlOps(
    descriptorPackage(CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME).ops,
  )[0]?.execute[0]?.sql
  if (!install || !carrier302 || !carrier304 || bundle304 === undefined) {
    throw new Error('shipped artefacts no longer have the expected op shape')
  }

  const ops: readonly SqlMigrationOp[] = [
    {
      ...install,
      label: to304(install.label),
      execute: [
        {
          description: to304(install.execute[0]?.description ?? ''),
          sql: bundle304,
        },
      ],
    },
    // The 3.0.2 carrier is byte-identical across 1.0.0 and 3.0.5.
    carrier302,
    {
      ...carrier304,
      postcheck: carrier304.postcheck.map((check) => ({
        description: to304(check.description),
        sql: to304(check.sql),
      })),
    },
  ]

  const metadata: MigrationMetadata = {
    ...descriptorPackage(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME).metadata,
    providedInvariants: [...INVARIANTS_1_0_0],
    migrationHash: STALE_1_0_0_BASELINE_HASH,
  }

  return { metadata, ops }
}

/**
 * Write a `migrations/cipherstash/` directory exactly as
 * `@cipherstash/stack-prisma@1.0.0`'s seed phase would have left it: the
 * 1.0.0 baseline, the two upgrade edges 1.0.0 shipped (both unchanged by
 * the 3.0.5 release, so the shipped bytes ARE the 1.0.0 bytes), and a
 * head ref demanding only the three 1.0.0 invariants.
 */
async function vendorStale100Space(migrationsDir: string): Promise<void> {
  const spaceDir = spaceMigrationDirectory(migrationsDir, CIPHERSTASH_SPACE_ID)
  const stale = buildStale100Baseline()

  await emitContractSpaceArtefacts(migrationsDir, CIPHERSTASH_SPACE_ID, {
    contract: descriptorSpace().contractJson,
    contractDts: 'export {};\n',
    headRef: { hash: headRef.hash, invariants: [...INVARIANTS_1_0_0] },
  })

  await writeMigrationPackage(
    join(spaceDir, CIPHERSTASH_V3_BASELINE_MIGRATION_NAME),
    stale.metadata,
    stale.ops,
  )
  for (const dirName of [
    CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
    CIPHERSTASH_V3_304_UPGRADE_MIGRATION_NAME,
  ]) {
    await materialiseExtensionMigrationPackageIfMissing(
      spaceDir,
      descriptorPackage(dirName),
    )
  }
}

/**
 * The CLI's phase-1 seed, reproduced from its two public primitives —
 * `runContractSpaceSeedPhase` itself is not on `@prisma-next/cli`'s
 * exports map, and `materialiseExtensionMigrationPackageIfMissing`
 * documents this exact mirroring for extension-package tests. Order and
 * semantics match `contract-space-seed-phase.ts`: re-emit the framework-
 * owned artefacts unconditionally, then materialise only MISSING
 * packages.
 */
async function runSeedPhase(migrationsDir: string): Promise<readonly string[]> {
  const space = descriptorSpace()
  await emitContractSpaceArtefacts(migrationsDir, CIPHERSTASH_SPACE_ID, {
    contract: space.contractJson,
    contractDts: 'export {};\n',
    headRef: space.headRef,
  })
  const spaceDir = spaceMigrationDirectory(migrationsDir, CIPHERSTASH_SPACE_ID)
  const written: string[] = []
  for (const pkg of space.migrations) {
    const result = await materialiseExtensionMigrationPackageIfMissing(
      spaceDir,
      pkg,
    )
    if (result.written) written.push(pkg.dirName)
  }
  return written
}

async function applyPath(
  migrationsDir: string,
  marker: {
    readonly hash: string | null
    readonly invariants: readonly string[]
  },
) {
  return computeExtensionSpaceApplyPath({
    projectMigrationsDir: migrationsDir,
    spaceId: CIPHERSTASH_SPACE_ID,
    currentMarkerHash: marker.hash,
    currentMarkerInvariants: marker.invariants,
  })
}

function requireOk<T extends { kind: string }>(
  outcome: T,
): Extract<T, { kind: 'ok' }> {
  if (outcome.kind !== 'ok') {
    throw new Error(`expected an applicable path, got "${outcome.kind}"`)
  }
  return outcome as Extract<T, { kind: 'ok' }>
}

let migrationsDir: string
let root: string

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'cipherstash-stale-vendored-'))
  migrationsDir = join(root, 'migrations')
})

afterEach(async () => {
  await rm(root, { recursive: true, force: true })
})

describe('stale vendored migrations/cipherstash/ (generated against 1.0.0)', () => {
  it('the fixture IS the published 1.0.0 baseline — proved by its content hash', () => {
    // Content addressing turns this into an exact-bytes claim: only the
    // 1.0.0 artefact hashes to fc495f7f…. If this fails, the fixture is
    // no longer the thing consumers have on disk and every assertion
    // below is about a straw man.
    const stale = buildStale100Baseline()
    const { migrationHash: _stored, ...envelope } = stale.metadata
    expect(computeMigrationHash(envelope, stale.ops)).toBe(
      STALE_1_0_0_BASELINE_HASH,
    )
    // …and it is genuinely NOT what the package ships today.
    expect(v3BaselineMetadata.migrationHash).not.toBe(STALE_1_0_0_BASELINE_HASH)
    expect(v3BaselineMetadata.migrationHash).toBe(
      'sha256:23c98b0368d22794507a4ef7b02ed4cb04249f36bfcb0b20488005aa62488313',
    )
    // The stale bundle is 3.0.4: the old name only. Asserted on the STALE
    // side alone, deliberately — the shipped 3.0.5 bundle carries BOTH names
    // (the new one plus the old restored as a deprecated alias in upstream
    // 142f41d8), so `not.toContain('ste_vec_contains')` is false there and
    // would be the wrong shape of check. What distinguishes the two artefacts
    // is that 3.0.4 has no `jsonb_document_contains` at all.
    const staleSql = stale.ops[0]?.execute[0]?.sql ?? ''
    expect(staleSql).toContain('ste_vec_contains')
    expect(staleSql).not.toContain('jsonb_document_contains')
  })

  it('HEADLINE: the seed phase keeps the stale baseline and reports no problem', async () => {
    // This is the finding. `migrationHash` verifies a package against its
    // OWN bytes, and the vendored 1.0.0 copy is internally intact — so it
    // passes. The seed phase's by-existence skip never rewrites it and
    // never compares it to the descriptor. The upgrade is therefore
    // silent: no hash mismatch, no warning, no mention of the stale
    // directory anywhere in the pipeline.
    await vendorStale100Space(migrationsDir)
    const newlyWritten = await runSeedPhase(migrationsDir)

    // Only the 3.0.5 directory is new; the re-emitted baseline is NOT
    // re-materialised over the stale copy.
    expect(newlyWritten).toEqual([CIPHERSTASH_V3_305_UPGRADE_MIGRATION_NAME])

    const spaceDir = spaceMigrationDirectory(
      migrationsDir,
      CIPHERSTASH_SPACE_ID,
    )
    const onDiskBaseline = JSON.parse(
      await readFile(
        join(
          spaceDir,
          CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
          'migration.json',
        ),
        'utf8',
      ),
    ) as { migrationHash: string; providedInvariants: string[] }
    expect(onDiskBaseline.migrationHash).toBe(STALE_1_0_0_BASELINE_HASH)
    expect(onDiskBaseline.providedInvariants).toEqual([...INVARIANTS_1_0_0])

    // The integrity checker's own load-time verdict: clean.
    const { packages, problems } = await readMigrationsDir(spaceDir)
    expect(problems).toEqual([])
    expect(packages).toHaveLength(4)

    // …while `refs/head.json` IS overwritten, unconditionally, and now
    // demands an invariant the stale genesis edge does not provide. That
    // asymmetry (head ref refreshed, packages frozen) is the whole
    // failure mode.
    const onDiskHead = JSON.parse(
      await readFile(join(spaceDir, 'refs', 'head.json'), 'utf8'),
    ) as { invariants: string[] }
    expect(onDiskHead.invariants).toEqual([...headRef.invariants])
    expect(onDiskHead.invariants).toContain(
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle305,
    )
  })

  it('an existing 1.0.0 database still upgrades correctly — only the 3.0.5 edge runs', async () => {
    // The changeset's claim: "Your database keeps its markers, so
    // already-applied invariants are not re-run — the only new work is
    // the 3.0.5 upgrade edge." Verified here for the consumer who did
    // NOT delete the directory, which is the strictly harder case.
    await vendorStale100Space(migrationsDir)
    await runSeedPhase(migrationsDir)

    const outcome = requireOk(
      await applyPath(migrationsDir, {
        hash: headRef.hash,
        invariants: [...INVARIANTS_1_0_0],
      }),
    )
    expect(outcome.walkedMigrationDirs).toEqual([
      CIPHERSTASH_V3_305_UPGRADE_MIGRATION_NAME,
    ])
    expect(outcome.providedInvariants).toEqual([
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle305,
    ])
    // The baseline is NOT re-run, so no marker-recorded invariant is
    // re-applied and the stale bundle is never re-installed over 3.0.5.
    const ops = asSqlOps(outcome.pathOps)
    expect(ops.map((op) => op.id)).toEqual([
      'cipherstash.upgrade-eql-v3-bundle-3.0.5',
    ])
    expect(ops[0]?.execute[0]?.sql).toContain('eql_v3.jsonb_document_contains')
  })

  it('…and identically for a consumer who DID follow the instruction', async () => {
    // Deleting `migrations/cipherstash/` and re-running `migration plan`
    // regenerates the directory from the descriptor. For an existing
    // database the plan is the same single edge — so following the
    // instruction costs nothing and changes nothing here. The difference
    // only shows up on a fresh database (next two tests).
    await runSeedPhase(migrationsDir)
    const outcome = requireOk(
      await applyPath(migrationsDir, {
        hash: headRef.hash,
        invariants: [...INVARIANTS_1_0_0],
      }),
    )
    expect(outcome.walkedMigrationDirs).toEqual([
      CIPHERSTASH_V3_305_UPGRADE_MIGRATION_NAME,
    ])
  })

  it('an already-3.0.5 database is a no-op — the upgrade edge does not re-run', async () => {
    await runSeedPhase(migrationsDir)
    const outcome = requireOk(
      await applyPath(migrationsDir, {
        hash: headRef.hash,
        invariants: [...headRef.invariants],
      }),
    )
    expect(outcome.walkedMigrationDirs).toEqual([])
    expect(outcome.pathOps).toEqual([])
  })
})

describe('fresh database: both install paths must converge on eql-3.0.5', () => {
  it('a clean vendored space installs 3.0.5 from the genesis edge alone', async () => {
    await runSeedPhase(migrationsDir)
    const outcome = requireOk(
      await applyPath(migrationsDir, { hash: null, invariants: [] }),
    )
    expect(outcome.walkedMigrationDirs).toEqual([
      CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
    ])
    expect(outcome.providedInvariants).toEqual([...headRef.invariants].sort())

    const ops = asSqlOps(outcome.pathOps)
    expect(ops[0]?.execute[0]?.sql).toContain('eql_v3.jsonb_document_contains')
    // Every op additive, so `db init`'s additive-only policy accepts it.
    expect(opsRefusedByDbInitPolicy(ops)).toEqual([])
  })

  it('a STALE vendored space still converges on 3.0.5 under `migrate` — but installs the bundle twice', async () => {
    // `prisma-next migrate` allows every operation class, so it can walk
    // the data-classed 3.0.5 self-edge. The end state is correct; the
    // cost is that the stale genesis edge installs eql-3.0.4 first and
    // the upgrade edge immediately re-installs eql-3.0.5 over it (the
    // bundle SQL is re-install-safe, which is what makes this survivable
    // rather than broken).
    await vendorStale100Space(migrationsDir)
    await runSeedPhase(migrationsDir)

    const outcome = requireOk(
      await applyPath(migrationsDir, { hash: null, invariants: [] }),
    )
    expect(outcome.walkedMigrationDirs).toEqual([
      CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
      CIPHERSTASH_V3_305_UPGRADE_MIGRATION_NAME,
    ])
    expect(outcome.providedInvariants).toEqual([...headRef.invariants].sort())

    const ops = asSqlOps(outcome.pathOps)
    const bundleSql = ops
      .flatMap((op) => op.execute.map((step) => step.sql))
      .filter((sql) => sql.length > 0)
    expect(bundleSql).toHaveLength(2)
    expect(bundleSql[0]).toContain('ste_vec_contains')
    expect(bundleSql[1]).toContain('eql_v3.jsonb_document_contains')
  })

  it('DEFECT: a STALE vendored space breaks `db init`, and the refusal never names the stale directory', async () => {
    // `db init` runs additive-only. The stale genesis edge provides three
    // of the four head-ref invariants, so the planner has to reach for the
    // data-classed 3.0.5 self-edge — and the runner then refuses the run
    // with a POLICY_VIOLATION naming only an operation id.
    //
    // Pinned because it is the one path where ignoring the changeset's
    // "Action required" note actually fails, and because the message a
    // consumer sees is UNRELATED to the cause: nothing in it mentions the
    // vendored directory, the baseline re-emit, or the remedy. There is
    // no in-package lever to improve it — the text is produced by
    // `@prisma-next/target-postgres`'s `enforcePolicyCompatibility`, and
    // the operation id it interpolates is frozen inside a published,
    // content-addressed artefact. If this test starts failing because a
    // framework upgrade made the refusal self-describing, delete it.
    await vendorStale100Space(migrationsDir)
    await runSeedPhase(migrationsDir)

    const outcome = requireOk(
      await applyPath(migrationsDir, { hash: null, invariants: [] }),
    )
    const ops = asSqlOps(outcome.pathOps)
    expect(opsRefusedByDbInitPolicy(ops)).toEqual([
      'cipherstash.upgrade-eql-v3-bundle-3.0.5',
    ])

    // The exact refusal the user reads, reconstructed from the target's
    // template. It names an op id and a class; it does not name the
    // problem or the remedy.
    const refused = ops.find((op) => op.operationClass !== 'additive')
    const message = `Operation ${refused?.id} has class "${refused?.operationClass}" which is not allowed by policy.`
    expect(message).toBe(
      'Operation cipherstash.upgrade-eql-v3-bundle-3.0.5 has class "data" which is not allowed by policy.',
    )
    expect(message).not.toContain('migrations/cipherstash')
    expect(message).not.toContain('migration plan')

    // Since the message cannot be improved from inside this package, the
    // SHIPPED DOCS have to carry the bridge from that exact string to the
    // remedy. Pinned so they cannot drift apart: a user's only route from the
    // error to the fix is pasting it into a search.
    //
    // BOTH of them, and the skill is the one that was missed. The README ships
    // in the npm tarball and is read by a human who hit the error. `skills/`
    // ships inside the `stash` tarball and `installSkills()` copies it into the
    // user's `.claude/skills/` — so it is what an AGENT reads, and an agent
    // driving `db init` in a repo upgraded from 1.0.0 hits this refusal with no
    // route out of it. Nothing type-checks either file; this assertion is the
    // only thing holding the pair to the planner's real message.
    // `test/v3` -> `test` -> `packages/stack-prisma` -> `packages` -> root.
    const repoRoot = join(
      dirname(fileURLToPath(import.meta.url)),
      '..',
      '..',
      '..',
      '..',
    )
    const shipped = {
      'packages/stack-prisma/README.md': await readFile(
        join(repoRoot, 'packages/stack-prisma/README.md'),
        'utf8',
      ),
      'skills/stash-prisma/SKILL.md': await readFile(
        join(repoRoot, 'skills/stash-prisma/SKILL.md'),
        'utf8',
      ),
    }
    for (const [file, body] of Object.entries(shipped)) {
      expect(body, `${file} does not name the refusal`).toContain(message)
      expect(body, `${file} does not carry the remedy`).toContain(
        'rm -rf migrations/cipherstash',
      )
      expect(
        body,
        `${file} does not name the command that vendors it`,
      ).toContain('prisma-next migration plan')
    }
  })

  it('the same fresh `db init` succeeds once the instruction is followed', async () => {
    // Deleting the directory and re-running the seed phase is the whole
    // remedy: the regenerated genesis edge carries all four invariants as
    // additive ops, so nothing outside the policy is ever planned.
    await vendorStale100Space(migrationsDir)
    await rm(spaceMigrationDirectory(migrationsDir, CIPHERSTASH_SPACE_ID), {
      recursive: true,
      force: true,
    })
    await runSeedPhase(migrationsDir)

    const outcome = requireOk(
      await applyPath(migrationsDir, { hash: null, invariants: [] }),
    )
    const ops = asSqlOps(outcome.pathOps)
    expect(opsRefusedByDbInitPolicy(ops)).toEqual([])
    expect(outcome.walkedMigrationDirs).toEqual([
      CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
    ])
  })
})

/**
 * The seed phase runs from ONE command. `runContractSpaceSeedPhase` is
 * called only by `prisma-next migration plan`
 * (`@prisma-next/cli/src/commands/migration-plan.ts`); `migrate`,
 * `db init` and `db update` plan straight from whatever is on disk. So a
 * consumer who upgrades the package and runs `migrate` — without a
 * `migration plan` first — never materialises the 3.0.5 directory and
 * never re-pins `refs/head.json`.
 *
 * This is not specific to the 3.0.5 re-emit (it was equally true of the
 * append-only 3.0.2 and 3.0.4 bumps), but it IS the shape the changeset's
 * "re-install through this edge on the next `prisma-next migrate`"
 * sentence gets wrong, and it is the only path in this whole area that
 * fails silently rather than loudly.
 */
describe('no seed phase run: the 3.0.5 upgrade is silently invisible', () => {
  it('`migrate` against an existing 1.0.0 database is a no-op — 3.0.5 never applies', async () => {
    await vendorStale100Space(migrationsDir)
    // deliberately NO runSeedPhase — the user ran `migrate`, not `plan`

    const outcome = requireOk(
      await applyPath(migrationsDir, {
        hash: headRef.hash,
        invariants: [...INVARIANTS_1_0_0],
      }),
    )
    // No error, no warning, no work: the on-disk head ref still demands
    // only the three 1.0.0 invariants, which the marker already has.
    expect(outcome.walkedMigrationDirs).toEqual([])
    expect(outcome.pathOps).toEqual([])
    expect(outcome.contractSpaceHeadRef.invariants).not.toContain(
      CIPHERSTASH_V3_INVARIANTS.upgradeBundle305,
    )
  })

  it('`db init` against a fresh database silently installs eql-3.0.4', async () => {
    await vendorStale100Space(migrationsDir)
    // deliberately NO runSeedPhase

    const outcome = requireOk(
      await applyPath(migrationsDir, { hash: null, invariants: [] }),
    )
    const ops = asSqlOps(outcome.pathOps)
    // Succeeds — every op is additive, so `db init`'s policy is happy…
    expect(opsRefusedByDbInitPolicy(ops)).toEqual([])
    // …and the database lands on the PREVIOUS bundle, with the marker
    // recording three invariants rather than four.
    expect(ops[0]?.execute[0]?.sql).toContain('ste_vec_contains')
    expect(ops[0]?.execute[0]?.sql).not.toContain('jsonb_document_contains')
    expect(outcome.providedInvariants).toEqual([...INVARIANTS_1_0_0].sort())
  })
})
