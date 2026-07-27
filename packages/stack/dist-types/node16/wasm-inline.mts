/**
 * The THIRD declaration artifact: `dist/wasm-inline.d.ts`.
 *
 * `tsup.config.ts` runs a second, independent DTS pass for the wasm-inline
 * entry, which inlines its own copy of `EncryptedV3Column` and the helpers that
 * invert its domain parameter. Neither the bundler gate nor the `.cts`/`.mts`
 * probes above reach it — they resolve `./v3` and `./eql/v3`, which come from
 * the first pass. So the entry documented for Workers, Deno, Bun and Supabase
 * Edge — the runtimes with the least margin for a broken type — was the one
 * artifact nothing typechecked.
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

import type {
  EncryptedTextSearchColumn,
  PlaintextForColumn,
  QueryTypesForColumn,
} from '@cipherstash/stack/wasm-inline'

const plaintext: string =
  null as unknown as PlaintextForColumn<EncryptedTextSearchColumn>
const queryTypes: 'equality' | 'orderAndRange' | 'freeTextSearch' =
  null as unknown as QueryTypesForColumn<EncryptedTextSearchColumn>
void plaintext
void queryTypes
