/**
 * The wasm-inline declaration artifact: `dist/wasm-inline.d.ts`.
 *
 * `tsup.config.ts` used to run a second, independent DTS pass for this entry,
 * which inlined its own copy of `EncryptedV3Column` and the helpers that invert
 * its domain parameter. Neither the bundler gate nor the `.cts`/`.mts` probes
 * above reached it — they resolve `./v3` and `./eql/v3`, which come from the
 * main pass. So the entry documented for Workers, Deno, Bun and Supabase
 * Edge — the runtimes with the least margin for a broken type — was the one
 * artifact nothing typechecked. Its declarations now come from the main config
 * so all entries share one set of chunks; `wasmTableCrossesEntries` below is
 * what holds that in place.
 *
 * `./wasm-inline` is ESM-only in the `exports` map (no `require` branch, by
 * design: the inlined WASM blob cannot be `require`d), hence `.mts` and no
 * `.cts` twin.
 *
 * `encryptQuery` is deliberately NOT column-narrowed on this entry
 * (`WasmEncryptQueryOptions.column` is wide), so this asserts the helpers
 * directly rather than through a call — they are what carries the domain, and
 * what collapses if the phantom carrier is lost on emit.
 */

import {
  type AnyV3Table as NativeAnyV3Table,
  encryptedTable as nativeEncryptedTable,
  types as nativeTypes,
} from '@cipherstash/stack/eql/v3'
import {
  type AnyV3Table,
  type EncryptedTextSearchColumn,
  encryptedTable,
  type PlaintextForColumn,
  type QueryTypesForColumn,
  types,
  Encryption as WasmEncryption,
} from '@cipherstash/stack/wasm-inline'

const plaintext: string =
  null as unknown as PlaintextForColumn<EncryptedTextSearchColumn>
const queryTypes: 'equality' | 'orderAndRange' | 'freeTextSearch' =
  null as unknown as QueryTypesForColumn<EncryptedTextSearchColumn>
void plaintext
void queryTypes

/**
 * The same schema-array shapes the native entry accepts (#815 review).
 *
 * `WasmEncryptionConfig.schemas` was a MUTABLE non-empty tuple long after A-4
 * widened the native twin, so the two entries disagreed about identical calls:
 * a `.map()` result or a `readonly` array compiled against `@cipherstash/stack`
 * and failed against `@cipherstash/stack/wasm-inline`, while their runtimes
 * agreed exactly (`!schemas.length`). Pinned against the built `.d.ts` because
 * this entry gets its own tsup DTS pass — a source-only type test cannot see it.
 */
const wasmUsers = encryptedTable('users', {
  email: types.TextSearch('email'),
})

const wasmConfig = {
  workspaceCrn: 'crn',
  accessKey: 'ak',
  clientId: 'id',
  clientKey: 'key',
}

/** The same table authored from the NATIVE entry, for the cross-entry probes. */
const nativeUsers = nativeEncryptedTable('users', {
  email: nativeTypes.TextSearch('email'),
})

/**
 * A wasm-inline-authored table must be the SAME type as an `./eql/v3` one.
 *
 * `EncryptedV3Column` carries `private readonly columnName`, and TypeScript
 * compares classes with private members by declaration origin rather than
 * structurally. While this entry got its own DTS pass it carried its own copy of
 * the class, so this assignment failed with "Types have separate declarations of
 * a private property 'columnName'" — and since every first-party adapter types
 * its `schemas` in terms of `AnyV3Table`, a table authored here could not be
 * passed to `encryptedSupabase`, the Drizzle helpers, or Prisma Next. The
 * runtime accepted it (`isV3ColumnLike` probes structurally); only the compiler
 * refused, which is why nothing but a gate over the emitted `.d.ts` caught it.
 *
 * The sibling `../wasm-inline-type-identity.ts` asserts the same identity under
 * `moduleResolution: bundler` over relative paths. This one resolves both
 * entries BY PACKAGE NAME through the `exports` map — the way a customer does.
 */
export const wasmTableCrossesEntries: NativeAnyV3Table = wasmUsers

/**
 * ...and the reverse direction: an `./eql/v3`-authored table into this entry's
 * `Encryption`. Asserted explicitly because the failure was symmetric — each
 * entry rejected the other's schema — so a fix that only made one direction work
 * would leave the shared-schema-module story broken and this gate green.
 */
export async function nativeTableIntoWasmClient() {
  await WasmEncryption({ schemas: [nativeUsers], config: wasmConfig })
}

export async function wasmSchemaShapes() {
  await WasmEncryption({ schemas: [wasmUsers], config: wasmConfig })

  const widened: AnyV3Table[] = [wasmUsers]
  await WasmEncryption({ schemas: widened, config: wasmConfig })

  const frozen: readonly AnyV3Table[] = [wasmUsers]
  await WasmEncryption({ schemas: frozen, config: wasmConfig })

  await WasmEncryption({
    schemas: [wasmUsers].map((t) => t),
    config: wasmConfig,
  })

  // @ts-expect-error - at least one table is required
  await WasmEncryption({ schemas: [], config: wasmConfig })
}

/**
 * `eqlVersion` must be rejected here exactly as it is on the native entry.
 *
 * This entry throws on the key at runtime (the guard mirrors the native one
 * byte for byte), so a config the type accepts and the factory rejects is the
 * same static/runtime disagreement #815 is about. A fresh literal was already
 * caught by excess-property checking; a HOISTED config — one shared const,
 * which is what a v2 → v3 migration actually holds — was not, because
 * excess-property checking does not apply to it. `eqlVersion?: never` on the
 * shared base of the `WasmClientConfig` intersection covers all three auth
 * arms at once.
 */
export async function wasmConfigShapes() {
  await WasmEncryption({
    schemas: [wasmUsers],
    // @ts-expect-error - `eqlVersion` was removed; this entry always emits v3
    config: { ...wasmConfig, eqlVersion: 2 },
  })

  const hoistedWasmConfig = { ...wasmConfig, eqlVersion: 2 }
  await WasmEncryption({
    schemas: [wasmUsers],
    // @ts-expect-error - rejected even when the config is not a fresh literal
    config: hoistedWasmConfig,
  })
}
