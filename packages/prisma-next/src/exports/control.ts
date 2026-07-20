/**
 * Control-plane descriptor for the CipherStash extension.
 *
 * **Contract-space package layout.** The extension's contract +
 * migrations are emitted by the same pipeline application authors use:
 *
 *   `prisma-next contract emit` → `<package>/src/contract.{json,d.ts}`
 *   `prisma-next migration plan` → `<package>/migrations/<dir>/...`
 *
 * The descriptor wires those JSON artefacts via JSON-import declarations
 * so they flow through the consuming application's module resolver
 * without filesystem assumptions, and synthesises the canonical
 * {@link import('@prisma-next/framework-components/control').MigrationPackage}
 * shape for the framework's runner / verifier to consume.
 *
 * Wired surfaces:
 *
 *   - `contractSpace.{contractJson,migrations,headRef}` — sourced from
 *     the on-disk artefacts emitted by `build:contract-space`.
 *   - `types.codecTypes.controlPlaneHooks` — the v3 codec-control hooks
 *     (`cipherstashV3CodecControlHooks`) the SQL planner extracts via
 *     `extractCodecControlHooks`. v3 registers the identity
 *     `expandNativeType` ONLY (the planner requires a hook to exist for
 *     `typeParams`-carrying columns) and NO `onFieldEvent`, so v3
 *     columns emit no `add_search_config` / `remove_search_config` ops —
 *     the v3 domains carry their own index metadata.
 *
 * @see docs/architecture docs/adrs/ADR 212 - Contract spaces.md
 *   (contract-space package layout convention).
 */

import type { Contract } from '@prisma-next/contract/types'
import type { SqlControlExtensionDescriptor } from '@prisma-next/family-sql/control'
import { contractSpaceFromJson } from '@prisma-next/migration-tools/spaces'
import type { SqlStorage } from '@prisma-next/sql-contract/types'
import v3BaselineMetadata from '../../migrations/20260601T0100_install_eql_v3_bundle/migration.json' with {
  type: 'json',
}
import v3BaselineOps from '../../migrations/20260601T0100_install_eql_v3_bundle/ops.json' with {
  type: 'json',
}
import headRef from '../../migrations/refs/head.json' with { type: 'json' }
import contractJson from '../contract.json' with { type: 'json' }
import { CIPHERSTASH_V3_BASELINE_MIGRATION_NAME } from '../extension-metadata/constants-v3'
import { cipherstashPackMeta } from '../extension-metadata/descriptor-meta'
import { cipherstashV3CodecControlHooks } from '../migration/cipherstash-codec-v3'
import { withRuntimeEqlSqlPackage } from '../migration/eql-bundle-v3'

const v3BaselineRuntimePackage = withRuntimeEqlSqlPackage(
  v3BaselineMetadata,
  v3BaselineOps,
)

const cipherstashContractSpace = contractSpaceFromJson<Contract<SqlStorage>>({
  contractJson,
  migrations: [
    // The v3 bundle baseline is the SOLE migration — the package is EQL
    // v3 only. It is an invariant-only genesis edge (`from: null` → the
    // empty-storage hash; the bundle creates `public.eql_v3_*` domains +
    // `eql_v3.*` functions but no contract-space storage). The v3 codec
    // ids ARE registered in `controlPlaneHooks` below, but with the
    // identity `expandNativeType` ONLY (the planner requires the hook to
    // exist for `typeParams`-carrying columns) — no `onFieldEvent`,
    // which is what guarantees v3 columns emit no `add_search_config` /
    // `remove_search_config` ops.
    {
      dirName: CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
      metadata: v3BaselineRuntimePackage.metadata,
      // The committed `ops.json` carries a placeholder in place of the ~1.7 MB
      // install SQL; inject it here from the installed `@cipherstash/eql` so
      // bumping the pinned EQL version needs no re-emit of the migration. The
      // helper also recomputes the content-addressed migration hash from the
      // injected ops so the descriptor can be materialised and verified.
      ops: v3BaselineRuntimePackage.ops,
    },
  ],
  headRef,
})

const cipherstashExtensionDescriptor: SqlControlExtensionDescriptor<'postgres'> =
  {
    // Spread pack-meta first so it contributes `kind` / `id` / `familyId`
    // / `targetId` / `version` / `authoring` / `types.{codecTypes,storage}`
    // — then overlay the contract-space block and the codec lifecycle
    // hook on top. The two `types.codecTypes` slots (`codecInstances`
    // from pack-meta, `controlPlaneHooks` from this descriptor) coexist
    // on the same path and are merged below.
    ...cipherstashPackMeta,
    contractSpace: cipherstashContractSpace,
    /**
     * Free-form `types.codecTypes.controlPlaneHooks` block — the SQL
     * family's `extractCodecControlHooks` (in `@prisma-next/family-sql/
     * control`) finds hooks via duck-typing on this exact path. Mirrors
     * pgvector's wiring at `packages/3-extensions/pgvector/src/exports/
     * control.ts`.
     */
    types: {
      ...cipherstashPackMeta.types,
      codecTypes: {
        ...cipherstashPackMeta.types.codecTypes,
        controlPlaneHooks: {
          // v3: identity expandNativeType only, no onFieldEvent — see
          // `../migration/cipherstash-codec-v3.ts`. This is the whole
          // control-plane hook set: the package is EQL v3 only.
          ...cipherstashV3CodecControlHooks,
        },
      },
    },
    create: () => ({
      familyId: 'sql' as const,
      targetId: 'postgres' as const,
    }),
  }

export { cipherstashExtensionDescriptor }
export default cipherstashExtensionDescriptor
