#!/usr/bin/env -S node
/**
 * CipherStash baseline migration — install the vendored EQL bundle.
 *
 * The contract IR (see `<package>/contract.json`) declares the
 * `eql_v2_configuration` table only — that's the single typed object
 * today's `SqlStorage` IR can model. The actual database state — the
 * `eql_v2` schema, the `eql_v2_configuration_state` enum, the
 * `eql_v2_encrypted` composite, the `eql_v2.bloom_filter` /
 * `hmac_256` / `blake3` domains, plus the ORE composites — is created
 * by the vendored EQL bundle SQL (see `../../src/migration/eql-bundle.ts`,
 * which re-exports the bundle from `eql-install.generated.ts`
 * byte-for-byte). The bundle also creates the `eql_v2_configuration`
 * table itself, so the planner-emitted
 * `createTable` op would conflict with the bundle's `CREATE TABLE`
 * and is intentionally dropped from this migration's `operations`
 * getter.
 *
 * Authoring loop: this file is hand-edited (see
 * `docs/architecture docs/adrs/ADR 212 - Contract spaces.md`'s
 * contract-space package layout section). Re-emit `ops.json` /
 * `migration.json` after edits via `node migration.ts`.
 */
import {
  Migration,
  MigrationCLI,
  rawSql,
} from '@prisma-next/target-postgres/migration'
import { CIPHERSTASH_INVARIANTS } from '../../src/extension-metadata/constants'
import { EQL_BUNDLE_SQL } from '../../src/migration/eql-bundle'

const INSTALL_LABEL =
  'Install EQL bundle (functions, operators, casts, op classes, schema, types)'

export default class M extends Migration {
  override describe() {
    return {
      from: null,
      to: 'sha256:3c0ac95bd99fd4105d62aab17cbc79e81c75ee6bc46435b6c86ce65e5e39fcd2',
    }
  }

  override get operations() {
    return [
      rawSql({
        id: 'cipherstash.install-eql-bundle',
        label: INSTALL_LABEL,
        operationClass: 'additive',
        invariantId: CIPHERSTASH_INVARIANTS.installBundle,
        target: { id: 'postgres' },
        precheck: [],
        execute: [{ description: INSTALL_LABEL, sql: EQL_BUNDLE_SQL }],
        postcheck: [
          {
            description: 'verify "eql_v2" schema exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v2')",
          },
          {
            // The composite type is created in the `public` schema
            // (not `eql_v2`) — by design. Customer data columns
            // declared as `eql_v2_encrypted` are pinned to the type's
            // OID and must survive a `DROP SCHEMA eql_v2 CASCADE`
            // re-install of the bundle without losing the columns.
            // Placing the composite outside the `eql_v2` namespace
            // decouples the type's lifecycle from the bundle's
            // functions / operators / casts.
            description:
              'verify "public.eql_v2_encrypted" composite type exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'public' AND t.typname = 'eql_v2_encrypted')",
          },
        ],
      }),
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
