#!/usr/bin/env -S node
/**
 * CipherStash v3 baseline migration — install the EQL v3 bundle.
 *
 * The install SQL IS baked into `ops.json`, embedded by this self-emit
 * script from the installed `@cipherstash/eql` and verified against the
 * release manifest's `installSqlSha256` before emission (see
 * `../../src/migration/eql-bundle-v3.ts` for the full rationale: the
 * framework treats migration packages as immutable-by-dirName and applies
 * them from disk without the descriptor, so the artefact's bytes ARE the
 * migration). The bundle creates the 40 `public.eql_v3_*` storage domains,
 * the `eql_v3` operator-function schema (`eql_v3.eq`, `eql_v3.ord_term`, …),
 * the `eql_v3.query_*` operand domains, and the `eql_v3_internal` helper
 * schema.
 *
 * This is the genesis migration of the cipherstash contract space (the
 * package is EQL v3 only), and it is an **invariant-only genesis edge**:
 * the v3 bundle declares no contract-space storage (no config table),
 * so `describe()` returns `from: null → to: <the empty-storage hash>`.
 * The edge exists to carry the `cipherstash:install-eql-v3-bundle-v1`
 * invariant: the apply-path planner (`findPathWithInvariants`) walks it
 * when the head ref requires that invariant.
 *
 * PUBLISHED — DO NOT RE-EMIT. This package's bytes are content-addressed
 * into consumer repos; a re-emit that changes them orphans every vendored
 * copy. An EQL version bump ships as a NEW upgrade migration directory
 * (see `20260720T0000_upgrade_eql_v3_3_0_2`), never as an edit here.
 *
 * TWO authorized re-emits have happened, both recorded here in full:
 *
 *   1. Pre-GA, on the 1.0 release branch: the install op was reclassified
 *      `data` → `additive`, the baked bundle was bumped to eql-3.0.4, and
 *      a no-SQL carrier op per upgrade invariant (3.0.2 and 3.0.4) was
 *      added so fresh-database `db init` passes its additive-only policy.
 *   2. For eql-3.0.5 (published 1.0.0 → next release): the baked bundle
 *      moved to eql-3.0.5 and a third carrier op was added for its
 *      invariant. Unlike (1) this rewrites a GA-published artefact, and
 *      it was taken deliberately: at 14 days and negligible adoption the
 *      blast radius was small and knowable, where the append-only
 *      alternative (a second `from: null` genesis edge carrying every
 *      invariant) would have added ~5 MB of duplicated bundle SQL to the
 *      tarball per EQL patch, permanently.
 *
 * Both re-emits changed the `migrationHash` and the baked
 * `installSqlSha256`. Consumers must delete `migrations/cipherstash/` and
 * re-run `prisma-next migration plan` to pick up the re-emitted artefacts;
 * databases keep their markers, so already-applied invariants are not
 * re-run.
 *
 * Neither re-emit moved `createdAt`, and neither should have. It reads like
 * provenance — new bytes under a July timestamp looks like an oversight, and
 * has been raised as one — but it is the PRIMARY TIE-BREAK KEY in the
 * migrator's neighbour ordering (`createdAt → to → migrationHash`, see
 * `findPath` / `findPathWithInvariants`). Re-emitting the same logical
 * migration must not shift its position in the graph, so the field stays put
 * and the re-emit record above is where the provenance actually lives. Pinned
 * explicitly in `test/v3/migration-v3.test.ts` so a future re-emit cannot move
 * it under cover of a re-pinned digest.
 *
 * The append-only rule is the default and holds for every release after
 * this one. Re-emitting again is a decision to be argued on adoption
 * numbers, not a routine step of an EQL bump: once this package has real
 * consumers, the second genesis edge is the correct shape and the size
 * cost is the price of not orphaning them.
 *
 * Authoring loop (pre-publication only): hand-edit, then re-emit
 * `ops.json` / `migration.json` via
 * `pnpm exec tsx migrations/20260601T0100_install_eql_v3_bundle/migration.ts`.
 */
import {
  Migration,
  MigrationCLI,
  rawSql,
} from '@prisma/orm-target-postgres/target/migration'
import { CIPHERSTASH_V3_INVARIANTS } from '../../src/extension-metadata/constants-v3'
import {
  readVerifiedInstallSql,
  releaseManifest,
} from '../../src/migration/eql-bundle-v3'

const INSTALL_LABEL = `Install EQL v3 bundle (eql-${releaseManifest.eqlVersion}: public.eql_v3_* domains + eql_v3.* functions)`

export default class M extends Migration {
  override describe() {
    return {
      from: null,
      to: '0c0734babd6eeb868fee1f281ca96963022475611560e9f170f465daa35f8599',
    }
  }

  override get operations() {
    return [
      rawSql({
        id: 'cipherstash.install-eql-v3-bundle',
        label: INSTALL_LABEL,
        // `additive` (previously `data`): the bundle only CREATEs new
        // objects — the `public.eql_v3_*` domains, the `eql_v3` /
        // `eql_v3_internal` schemas and their functions — and touches no
        // user data, so along the axis migration POLICIES classify
        // (can this op damage existing data?) `additive` is the truthful
        // answer. The practical stake: `db init` enforces an
        // additive-only policy, and a `data` class here made every
        // fresh-database init (e.g. Prisma Compute preview deploys)
        // fail with PN-RUN-3020.
        //
        // The earlier `data` classification existed to satisfy the
        // aggregate integrity checker's no-op self-edge rule
        // (`sameSourceAndTarget`) — but that rule only fires when
        // `from === to`, and this genesis edge runs `from: null` → the
        // empty-storage hash, which the checker does NOT treat as a
        // self-edge. Verified against `migration-tools`
        // `check-integrity.ts` 0.16.0. (The 3.0.2 upgrade edge IS a true
        // self-edge and keeps its `data` class for exactly that rule.)
        operationClass: 'additive',
        invariantId: CIPHERSTASH_V3_INVARIANTS.installBundle,
        target: { id: 'postgres' },
        precheck: [],
        // The full ~1.7 MB install SQL, read from the installed
        // `@cipherstash/eql` and digest-verified against its release
        // manifest at emit time. Baked so the migration hash covers the
        // exact bytes every consumer's apply will execute.
        execute: [
          { description: INSTALL_LABEL, sql: readVerifiedInstallSql() },
        ],
        postcheck: [
          {
            description: 'verify the "eql_v3" operator schema exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v3')",
          },
          {
            // The storage domains live in `public` (not `eql_v3`) — by
            // design, mirroring the v2 `public.eql_v2_encrypted`
            // rationale: customer data columns declared against the
            // domains must survive a `DROP SCHEMA eql_v3 CASCADE`
            // re-install of the operator functions without losing the
            // columns.
            description:
              'verify the concrete domain "public.eql_v3_text_search" exists',
            sql: "SELECT to_regtype('public.eql_v3_text_search') IS NOT NULL",
          },
          {
            description: 'verify the eql_v3.eq operator function exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'eql_v3' AND p.proname = 'eq')",
          },
        ],
      }),
      // Invariant carrier: the install op above already ships the pinned
      // release's bundle (eql-3.0.5 — `readVerifiedInstallSql()` is digest-
      // verified against the installed manifest), so a fresh database that
      // walks this genesis edge IS at the pinned release — a superset of
      // every earlier v3 surface, so the 3.0.2 invariant is honestly
      // satisfied too. Declaring the upgrade invariants here
      // lets the shortest-path planner (`computeExtensionSpaceApplyPath` /
      // `findPathWithDecision`) satisfy the head ref from this single
      // all-additive edge, so fresh-database `db init` (additive-only
      // policy) never needs to walk the `data`-classed upgrade self-edges.
      // Databases installed at an older bundle still reach the pinned
      // release through those upgrade edges via `migrate`, whose policy
      // allows all classes.
      rawSql({
        id: 'cipherstash.install-provides-eql-v3-3-0-2',
        label:
          'EQL 3.0.2 invariant — provided by the install bundle above (no additional SQL)',
        operationClass: 'additive',
        invariantId: CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
        target: { id: 'postgres' },
        precheck: [],
        execute: [],
        postcheck: [
          {
            description:
              'verify the eql_v3 operator schema exists (the bundle was installed by the preceding op)',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v3')",
          },
        ],
      }),
      rawSql({
        id: 'cipherstash.install-provides-eql-v3-3-0-4',
        label:
          'EQL 3.0.4 invariant — provided by the install bundle above (no additional SQL)',
        operationClass: 'additive',
        invariantId: CIPHERSTASH_V3_INVARIANTS.upgradeBundle304,
        target: { id: 'postgres' },
        precheck: [],
        execute: [],
        postcheck: [
          {
            description: `verify eql_v3.version() reports ${releaseManifest.eqlVersion}`,
            sql: `SELECT eql_v3.version() = '${releaseManifest.eqlVersion}'`,
          },
        ],
      }),
      // The pinned release IS 3.0.5, so the install op above satisfies this
      // invariant on the same terms as the two carriers before it. The
      // postcheck is identical to 3.0.4's by construction — both interpolate
      // the emit-time `releaseManifest.eqlVersion`, and one bundle satisfies
      // every invariant up to its own version.
      rawSql({
        id: 'cipherstash.install-provides-eql-v3-3-0-5',
        label:
          'EQL 3.0.5 invariant — provided by the install bundle above (no additional SQL)',
        operationClass: 'additive',
        invariantId: CIPHERSTASH_V3_INVARIANTS.upgradeBundle305,
        target: { id: 'postgres' },
        precheck: [],
        execute: [],
        postcheck: [
          {
            description: `verify eql_v3.version() reports ${releaseManifest.eqlVersion}`,
            sql: `SELECT eql_v3.version() = '${releaseManifest.eqlVersion}'`,
          },
        ],
      }),
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
