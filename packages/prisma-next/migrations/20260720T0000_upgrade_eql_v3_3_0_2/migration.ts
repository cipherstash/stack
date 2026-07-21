#!/usr/bin/env -S node
/**
 * Upgrade an existing EQL v3 installation to the pinned 3.0.2 bundle.
 *
 * This is a separate invariant-only edge from the original v3 baseline. A
 * database that already recorded the baseline invariant must still traverse
 * this edge, otherwise changing the runtime SQL behind that historical marker
 * would leave the database on the older EQL surface.
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

const UPGRADE_LABEL = `Upgrade EQL v3 bundle to eql-${releaseManifest.eqlVersion}`

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
        id: 'cipherstash.upgrade-eql-v3-bundle-3.0.2',
        label: UPGRADE_LABEL,
        operationClass: 'data',
        invariantId: CIPHERSTASH_V3_INVARIANTS.upgradeBundle302,
        target: { id: 'postgres' },
        precheck: [],
        execute: [
          { description: UPGRADE_LABEL, sql: RUNTIME_EQL_SQL_SENTINEL },
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
