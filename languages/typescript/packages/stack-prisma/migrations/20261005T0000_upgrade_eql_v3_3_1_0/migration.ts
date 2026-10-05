#!/usr/bin/env -S node
/**
 * Upgrade an existing EQL v3 installation to the pinned 3.1.0 bundle.
 *
 * 3.1.0 is a minor release for the Rust `eql-bindings` crate. Its install
 * SQL changes only the version stamp (`eql_v3.version()` and the `eql_v3`
 * schema comment), but the bundle digest still moves, so it is still a new
 * bundle to install.
 *
 * A database that already recorded the earlier upgrade invariants must
 * still traverse this edge, or it stays on an older EQL surface. Fresh
 * databases never walk it: the baseline bakes 3.1.0 and carries this
 * invariant itself, which keeps `db init` (additive-only policy) working.
 *
 * A 1.2.x database (eql-3.0.6) walks only this edge. A 1.0.0 / 1.1.x one
 * (eql-3.0.4) walks the 3.0.5, 3.0.6 and 3.1.0 edges, installing the
 * ~2.6 MB bundle three times in one `migrate` — a time cost, not a
 * correctness problem.
 *
 * PUBLISHED — DO NOT RE-EMIT. These bytes are content-addressed into
 * consumer repos (`test/v3/migration-v3.test.ts` pins the hash). A future
 * EQL version ships as a NEW upgrade directory modelled on this one.
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

const EDGE_RELEASE = '3.1.0'

const UPGRADE_LABEL = `Upgrade EQL v3 bundle to eql-${releaseManifest.eqlVersion}`

export default class M extends Migration {
  override describe() {
    // Invariant-only self-edge on the empty-storage hash the baseline
    // lands on.
    return {
      from: '0c0734babd6eeb868fee1f281ca96963022475611560e9f170f465daa35f8599',
      to: '0c0734babd6eeb868fee1f281ca96963022475611560e9f170f465daa35f8599',
    }
  }

  override get operations() {
    // In the getter, not at module scope: only an emit reads `operations`.
    // Without it, an emit against any other installed release bakes that
    // release's SQL under this edge's 3.1.0 id.
    if (releaseManifest.eqlVersion !== EDGE_RELEASE) {
      throw new Error(
        `This edge bakes eql-${EDGE_RELEASE}, but the installed @cipherstash/eql is ` +
          `${releaseManifest.eqlVersion}. Published edges are never re-emitted; see DEVELOPING.md.`,
      )
    }
    return [
      rawSql({
        id: 'cipherstash.upgrade-eql-v3-bundle-3.1.0',
        label: UPGRADE_LABEL,
        // The integrity checker rejects a self-edge with no data-class op,
        // so only `migrate` (all classes allowed) can walk this edge.
        operationClass: 'data',
        invariantId: CIPHERSTASH_V3_INVARIANTS.upgradeBundle310,
        target: { id: 'postgres' },
        precheck: [],
        // Re-installing is safe: the bundle drops and recreates the
        // `eql_v3` schema but keeps the `public.eql_v3_*` storage domains
        // that customer columns depend on.
        execute: [
          { description: UPGRADE_LABEL, sql: readVerifiedInstallSql() },
        ],
        postcheck: [
          {
            description: `verify eql_v3.version() reports ${releaseManifest.eqlVersion}`,
            sql: `SELECT eql_v3.version() = '${releaseManifest.eqlVersion}'`,
          },
          {
            description: `verify the eql_v3 schema comment reports ${releaseManifest.eqlVersion}`,
            sql: `SELECT obj_description('eql_v3'::regnamespace, 'pg_namespace') = '${releaseManifest.eqlVersion}'`,
          },
          {
            description: 'verify the typed JSON query domain exists',
            sql: "SELECT to_regtype('eql_v3.query_json') IS NOT NULL",
          },
        ],
      }),
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
