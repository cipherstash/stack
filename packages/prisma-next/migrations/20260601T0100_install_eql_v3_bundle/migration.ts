#!/usr/bin/env -S node
/**
 * CipherStash EQL v3 baseline migration — install the vendored eql_v3 bundle.
 *
 * Mirrors the v2 baseline (`../20260601T0000_install_eql_bundle/migration.ts`)
 * but installs the **eql_v3** bundle: the `eql_v3` schema, the `eql_v3.text*`
 * domains (`text`, `text_eq`, `text_match`, `text_ord`), and the index-term
 * extractor functions. The bundle flows in byte-for-byte under the
 * `cipherstash:install-eql-v3-bundle-v1` invariant.
 *
 * Unlike v2, v3 emits NO `add_search_config` rows — the per-column domain type
 * (applied via the codec hook's `expandNativeType`) encodes the index capability.
 *
 * Authoring loop: hand-edited; re-emit `ops.json` / `migration.json` after edits
 * via `node migration.ts`.
 */
import { Migration, MigrationCLI, rawSql } from '@prisma-next/target-postgres/migration';
import { CIPHERSTASH_INVARIANTS } from '../../src/extension-metadata/constants';
import { EQL_V3_BUNDLE_SQL } from '../../src/migration/eql-v3-bundle';

const INSTALL_LABEL = 'Install EQL v3 bundle (eql_v3 schema, text domains, index-term extractors)';

export default class M extends Migration {
  override describe() {
    // The v3 bundle installs the eql_v3 schema/domains/functions but adds NO
    // contract-IR object (no tables modelled), so the resulting storage hash is
    // unchanged from the v2 baseline — `to` equals the package's contract
    // storageHash. v3 is therefore a parallel install baseline (from: null)
    // satisfying its own invariant; the head ref's invariant set is the union of
    // both baselines.
    return {
      from: null,
      to: 'sha256:efa685171bebbb8f078f08d12be3578bb5d96b71669dccc6cc9e4be96af8cdb4',
    };
  }

  override get operations() {
    return [
      rawSql({
        id: 'cipherstash.install-eql-v3-bundle',
        label: INSTALL_LABEL,
        operationClass: 'additive',
        invariantId: CIPHERSTASH_INVARIANTS.installBundleV3,
        target: { id: 'postgres' },
        precheck: [],
        execute: [{ description: INSTALL_LABEL, sql: EQL_V3_BUNDLE_SQL }],
        postcheck: [
          {
            description: 'verify "eql_v3" schema exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v3')",
          },
          {
            description: 'verify "eql_v3.text_eq" domain exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'eql_v3' AND t.typname = 'text_eq')",
          },
        ],
      }),
    ];
  }
}

MigrationCLI.run(import.meta.url, M);
