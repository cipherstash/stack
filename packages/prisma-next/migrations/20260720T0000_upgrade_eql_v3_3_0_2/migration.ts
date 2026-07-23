#!/usr/bin/env -S node
/**
 * Upgrade an existing EQL v3 installation to the pinned 3.0.2 bundle.
 *
 * This is a separate invariant-only edge from the original v3 baseline. A
 * database that already recorded the baseline invariant must still traverse
 * this edge, otherwise changing the SQL behind that historical marker
 * would leave the database on the older EQL surface.
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
        id: 'cipherstash.upgrade-eql-v3-bundle-3.0.2',
        label: UPGRADE_LABEL,
        operationClass: 'data',
        invariantId: CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
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
            description: 'verify the typed text-match query domain exists',
            sql: "SELECT to_regtype('eql_v3.query_text_match') IS NOT NULL",
          },
        ],
      }),
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
