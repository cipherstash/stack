#!/usr/bin/env -S node
/**
 * Upgrade an existing EQL v3 installation to the pinned 3.0.5 bundle.
 *
 * 3.0.5 renames `eql_v3.ste_vec_contains` to `eql_v3.jsonb_document_contains`,
 * consolidating the last `ste_vec_*`-named public object into the `jsonb_*`
 * family. The operators are unchanged; only callers that invoke the function
 * by name (Supabase / PostgREST) are affected.
 *
 * This is a separate invariant-only edge from the v3 baseline. A database
 * that already recorded the baseline (and/or 3.0.2 / 3.0.4) invariant must
 * still traverse this edge, otherwise changing the SQL behind those
 * historical markers would leave the database on an older EQL surface.
 * Fresh databases never walk it: the re-emitted install baseline bakes the
 * 3.0.5 bundle and carries this invariant itself, so the shortest-path
 * planner satisfies the head ref from the all-additive genesis edge — which
 * is what keeps `db init` (additive-only policy) working.
 *
 * PUBLISHED — DO NOT RE-EMIT. This package's bytes are content-addressed
 * into consumer repos (the frozen-hash pin in
 * `test/v3/migration-v3.test.ts` fails on any change). A future EQL
 * version ships as a NEW `migrations/<ts>_upgrade_eql_v3_<x>_<y>_<z>/`
 * directory with a fresh invariant, modelled on this one — never as an
 * edit here.
 */
import {
  Migration,
  MigrationCLI,
  rawSql,
} from '@prisma-next/target-postgres/migration'
import { CIPHERSTASH_V3_INVARIANTS } from '../../src/extension-metadata/constants-v3'
import {
  readVerifiedInstallSql,
  releaseManifest,
} from '../../src/migration/eql-bundle-v3'

const UPGRADE_LABEL = `Upgrade EQL v3 bundle to eql-${releaseManifest.eqlVersion}`

export default class M extends Migration {
  override describe() {
    // Invariant-only self-edge on the v3-only contract space's
    // empty-storage hash — the same `to` the baseline lands on.
    return {
      from: 'sha256:efd408cf8924b4d1805bf5acced8898114aa03cd46b465720179c82a4431d51e',
      to: 'sha256:efd408cf8924b4d1805bf5acced8898114aa03cd46b465720179c82a4431d51e',
    }
  }

  override get operations() {
    return [
      rawSql({
        id: 'cipherstash.upgrade-eql-v3-bundle-3.0.5',
        label: UPGRADE_LABEL,
        // `data` is required here: this IS a true self-edge (from === to),
        // and the aggregate integrity checker rejects a self-edge without a
        // data-class op as a no-op. Only `migrate` (whose policy allows all
        // classes) ever needs to walk it.
        operationClass: 'data',
        invariantId: CIPHERSTASH_V3_INVARIANTS.upgradeBundle305,
        target: { id: 'postgres' },
        precheck: [],
        // The full install SQL, digest-verified at emit time (the EQL v3
        // install bundle is idempotent-by-reinstall: it drops and
        // recreates the `eql_v3` operator schema while preserving the
        // `public.eql_v3_*` storage domains customer columns depend on).
        execute: [
          { description: UPGRADE_LABEL, sql: readVerifiedInstallSql() },
        ],
        postcheck: [
          {
            description: `verify eql_v3.version() reports ${releaseManifest.eqlVersion}`,
            sql: `SELECT eql_v3.version() = '${releaseManifest.eqlVersion}'`,
          },
          {
            description: 'verify the typed JSON query domain exists',
            sql: "SELECT to_regtype('eql_v3.query_json') IS NOT NULL",
          },
          {
            // The rename this release carries: the old `ste_vec_contains`
            // name is gone, so assert the new one is what the reinstall
            // left behind.
            description:
              'verify the renamed eql_v3.jsonb_document_contains function exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'eql_v3' AND p.proname = 'jsonb_document_contains')",
          },
        ],
      }),
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
