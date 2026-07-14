#!/usr/bin/env -S node
/**
 * CipherStash v3 baseline migration — install the EQL v3 bundle.
 *
 * The install SQL is sourced at EMIT time from `@cipherstash/eql/sql`
 * (see `../../src/migration/eql-bundle-v3.ts` — the same source the
 * stack's `installEqlV3IfNeeded` uses) and baked into `ops.json`
 * byte-for-byte. The bundle creates the 40 `public.eql_v3_*` storage
 * domains, the `eql_v3` operator-function schema (`eql_v3.eq`,
 * `eql_v3.ord_term`, …), the `eql_v3.query_*` operand domains, and the
 * `eql_v3_internal` helper schema.
 *
 * This is the SECOND migration in the cipherstash contract space, and
 * it is an **invariant-only edge**: the v3 bundle declares no
 * contract-space storage (no config table — unlike the v2 bundle's
 * `eql_v2_configuration`), so the storage hash does not move and
 * `describe()` returns `from === to === <the v2 baseline's to>`. The
 * edge exists to carry the `cipherstash:install-eql-v3-bundle-v1`
 * invariant: the apply-path planner (`findPathWithInvariants`) walks it
 * when the head ref requires that invariant.
 *
 * Authoring loop: this file is hand-edited (see
 * `docs/architecture docs/adrs/ADR 212 - Contract spaces.md`'s
 * contract-space package layout section). Re-emit `ops.json` /
 * `migration.json` after edits via
 * `pnpm exec tsx migrations/20260601T0100_install_eql_v3_bundle/migration.ts`.
 */
import {
  Migration,
  MigrationCLI,
  rawSql,
} from '@prisma-next/target-postgres/migration'
import { CIPHERSTASH_V3_INVARIANTS } from '../../src/extension-metadata/constants-v3'
import {
  readInstallSql,
  releaseManifest,
} from '../../src/migration/eql-bundle-v3'

const INSTALL_LABEL = `Install EQL v3 bundle (eql-${releaseManifest.eqlVersion}: public.eql_v3_* domains + eql_v3.* functions)`

export default class M extends Migration {
  override describe() {
    return {
      from: 'sha256:1e86a0160ba305fa74516b6d9449218308b258a51a913c1fc907e629f44568a7',
      to: 'sha256:1e86a0160ba305fa74516b6d9449218308b258a51a913c1fc907e629f44568a7',
    }
  }

  override get operations() {
    return [
      rawSql({
        id: 'cipherstash.install-eql-v3-bundle',
        label: INSTALL_LABEL,
        // `data`, not `additive`: this edge is a SELF-EDGE (`from ===
        // to` — the bundle declares no contract-space storage), and the
        // aggregate integrity checker (`migration-tools`
        // `check-integrity.ts`) rejects a self-edge unless it carries a
        // `data`-class op. Along the axis the checker classifies —
        // does the op move the modeled contract shape? — `data` is the
        // truthful answer: the bundle creates `public.eql_v3_*` domains
        // and `eql_v3.*` functions the space contract deliberately does
        // not model. (Contrast the v2 bundle op: `additive`, because
        // its edge really moves the hash by adding the
        // `eql_v2_configuration` table.) The `migrate` policy allows
        // all four classes, so apply behaviour is unchanged.
        operationClass: 'data',
        invariantId: CIPHERSTASH_V3_INVARIANTS.installBundle,
        target: { id: 'postgres' },
        precheck: [],
        execute: [{ description: INSTALL_LABEL, sql: readInstallSql() }],
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
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
