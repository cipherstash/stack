/**
 * The TYPE-level half of the two-copies-of-a-class hazard that `isV3ColumnLike`
 * (`packages/stack-supabase/src/column-map.ts`) fixed at runtime.
 *
 * `EncryptedV3Column` carries `private readonly columnName`, and TypeScript
 * compares classes with private members by DECLARATION ORIGIN, not
 * structurally. So the moment two entries of this package ship two separately
 * emitted declarations of that class, a table authored from one is a COMPILE
 * error against the other — even though the runtime accepts it.
 *
 * That is what `tsup.config.ts` used to do: the wasm-inline config ran its own
 * DTS pass, which inlined a private copy of every column class instead of
 * sharing the `types-public-*.d.ts` chunk that `./eql/v3` and `./adapter-kit`
 * both reference. A table authored with `encryptedTable`/`types` from
 * `@cipherstash/stack/wasm-inline` therefore failed to typecheck against every
 * first-party adapter's `schemas`:
 *
 *     error TS2322: Type 'EncryptedV3Table<…>' is not assignable to type
 *     'AnyV3Table'. Types have separate declarations of a private property
 *     'columnName'.
 *
 * `wasm-inline` is the entry the edge examples use, so that was the published
 * shape for Workers, Deno, Bun and Supabase Edge. `tsup.config.ts` now emits
 * the wasm-inline declarations from the MAIN config so both entries resolve one
 * declaration; give that config its own `dts` back, rebuild, and this file fails
 * to compile.
 *
 * Lives here rather than in a `test-d`/vitest typecheck suite because those
 * resolve `@cipherstash/stack/*` to `../stack/src` (see
 * `packages/stack-supabase/tsconfig.json`) — source against source, which never
 * sees how the subpaths resolve for an installed consumer. Only a gate that
 * reads `dist/` can. This one uses `moduleResolution: bundler` over relative
 * paths; `node16/wasm-inline.mts` asserts the same thing by package name through
 * the `exports` map.
 */

import {
  Encryption as NativeEncryption,
  encryptedTable as nativeEncryptedTable,
  types as nativeTypes,
} from '../dist/encryption/v3.js'
import type { AnyV3Table } from '../dist/eql/v3/index.js'
import {
  Encryption as WasmEncryption,
  encryptedTable as wasmEncryptedTable,
  types as wasmTypes,
} from '../dist/wasm-inline.js'

const wasmUsers = wasmEncryptedTable('users', {
  email: wasmTypes.TextSearch('email'),
  amount: wasmTypes.IntegerOrd('amount'),
})

/**
 * The assertion. Every first-party adapter types its `schemas` option in terms
 * of `AnyV3Table`, so a wasm-inline-authored table that is not assignable here
 * cannot be passed to `encryptedSupabase`, the Drizzle helpers, or Prisma Next.
 *
 * `@cipherstash/stack-supabase` is the concrete case, and this line is what
 * replaced a text-level guard over it. `V3Schemas = Record<string, AnyV3Table>`
 * (`packages/stack-supabase/src/schema-builder.ts:7`) imports `AnyV3Table` from
 * `@cipherstash/stack/eql/v3` — the same declaration resolved here — so pinning
 * assignability to it pins the adapter pairing too, without this package taking
 * a build-graph dependency on one that depends on it.
 *
 * `scripts/__tests__/skills-supabase-edge-schema-entry.test.mjs` used to grep
 * shipped docs for a snippet pairing `encryptedSupabase` from the adapter's
 * wasm-inline entry with `encryptedTable`/`types` from
 * `@cipherstash/stack/wasm-inline`, on the grounds that it did not compile. It
 * compiles now, and that is the point of this file — so the guard was deleted
 * rather than reworded. A guard asserting a false claim is worse than no guard:
 * it would have blocked the first person to write the example the `stash-edge`
 * skill now recommends, citing a compiler error that no longer happens.
 */
export const wasmTableIsAV3Table: AnyV3Table = wasmUsers

/**
 * The column class itself, not just the table wrapper.
 *
 * The table assignment above happens to surface the diagnostic today, but it
 * does so through `columnBuilders`. Pinning a bare column too means the gate
 * still fails if `AnyV3Table` is ever loosened to erase its column types.
 */
export const wasmColumnIsAV3Column: AnyV3Table['columnBuilders'][string] =
  wasmTypes.TextSearch('email')

/**
 * A schema module authored on either entry must build EITHER client.
 *
 * This is the shape the `stash-edge` skill documents: one `schema.ts` shared
 * between a Node server and an Edge Function. Both directions are pinned because
 * the failure was symmetric — each entry rejected the other's schema — so a fix
 * that only worked one way would leave the shared-module story broken.
 *
 * `@cipherstash/stack/v3` is named explicitly rather than left to transitivity
 * through `./eql/v3`: it is the entry the skills tell people to author against.
 */
const nativeUsers = nativeEncryptedTable('users', {
  email: nativeTypes.TextSearch('email'),
})

export async function schemaModulesCrossEntries() {
  await NativeEncryption({ schemas: [nativeUsers] })
  await NativeEncryption({ schemas: [wasmUsers] })

  const wasmConfig = {
    workspaceCrn: 'crn',
    accessKey: 'ak',
    clientId: 'id',
    clientKey: 'key',
  }
  await WasmEncryption({ schemas: [wasmUsers], config: wasmConfig })
  await WasmEncryption({ schemas: [nativeUsers], config: wasmConfig })
}
