#!/usr/bin/env -S node
/**
 * CipherStash v3 baseline migration — install the EQL v3 bundle.
 *
 * The install SQL is NOT baked into `ops.json`. The committed op carries
 * `RUNTIME_EQL_SQL_SENTINEL`; `src/exports/control.ts` injects
 * `readInstallSql()` from the installed `@cipherstash/eql` at descriptor-build
 * time and recomputes the migration hash from those runtime ops (see
 * `../../src/migration/eql-bundle-v3.ts` `withRuntimeEqlSqlPackage`), so bumping
 * the pinned `@cipherstash/eql` needs no re-emit of this ~1.7 MB `ops.json`.
 * The bundle creates the 40 `public.eql_v3_*` storage domains, the `eql_v3`
 * operator-function schema (`eql_v3.eq`, `eql_v3.ord_term`, …), the
 * `eql_v3.query_*` operand domains, and the `eql_v3_internal` helper schema.
 *
 * This is the SOLE migration in the cipherstash contract space (the
 * package is EQL v3 only), and it is an **invariant-only genesis edge**:
 * the v3 bundle declares no contract-space storage (no config table),
 * so `describe()` returns `from: null → to: <the empty-storage hash>`.
 * The edge exists to carry the `cipherstash:install-eql-v3-bundle-v1`
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
  RUNTIME_EQL_SQL_SENTINEL,
  releaseManifest,
} from '../../src/migration/eql-bundle-v3'

const INSTALL_LABEL = `Install EQL v3 bundle (eql-${releaseManifest.eqlVersion}: public.eql_v3_* domains + eql_v3.* functions)`

export default class M extends Migration {
  override describe() {
    return {
      from: null,
      to: 'sha256:efd408cf8924b4d1805bf5acced8898114aa03cd46b465720179c82a4431d51e',
    }
  }

  override get operations() {
    return [
      rawSql({
        id: 'cipherstash.install-eql-v3-bundle',
        label: INSTALL_LABEL,
        // `data`, not `additive`: this genesis edge moves NO contract
        // storage (`from: null` → the empty-storage hash — the bundle
        // declares no contract-space storage), and the aggregate
        // integrity checker (`migration-tools` `check-integrity.ts`)
        // rejects a no-storage-movement edge unless it carries a
        // `data`-class op. Along the axis the checker classifies — does
        // the op move the modeled contract shape? — `data` is the
        // truthful answer: the bundle creates `public.eql_v3_*` domains
        // and `eql_v3.*` functions the space contract deliberately does
        // not model. The `migrate` policy allows all four classes, so
        // apply behaviour is unchanged.
        operationClass: 'data',
        invariantId: CIPHERSTASH_V3_INVARIANTS.installBundle,
        target: { id: 'postgres' },
        precheck: [],
        // Placeholder only — the real install SQL is injected at descriptor
        // build time from the installed `@cipherstash/eql` (see
        // `../../src/migration/eql-bundle-v3.ts` `withRuntimeEqlSql`), so the
        // ~1.7 MB bundle is NOT baked into `ops.json` and bumping the pinned
        // `@cipherstash/eql` needs no re-emit. Safe because this is an
        // invariant-only genesis edge: the SQL never moves the contract
        // hash (`from: null` → the empty-storage hash, as above).
        execute: [
          { description: INSTALL_LABEL, sql: RUNTIME_EQL_SQL_SENTINEL },
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
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
