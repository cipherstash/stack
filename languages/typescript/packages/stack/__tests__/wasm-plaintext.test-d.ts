import { describe, expectTypeOf, it } from 'vitest'
import type { WasmPlaintext } from '@/wasm-inline'

// `WasmPlaintext` is the plaintext type accepted by `encrypt` and returned by
// `decrypt` on the WASM entry point. It must admit `bigint` (int8 columns):
// protect-ffi 0.28's wasm build carries a native `bigint` across the boundary
// (`encode_plaintext` on encrypt, `js_sys::BigInt` on decrypt), so the SDK type
// must not narrow it out — otherwise bigint columns are unusable on WASM even
// though the runtime supports them.
describe('WasmPlaintext admits bigint', () => {
  it('accepts a bigint value', () => {
    expectTypeOf<bigint>().toMatchTypeOf<WasmPlaintext>()
  })

  it('still accepts the base scalar plaintext types', () => {
    expectTypeOf<string>().toMatchTypeOf<WasmPlaintext>()
    expectTypeOf<number>().toMatchTypeOf<WasmPlaintext>()
    expectTypeOf<boolean>().toMatchTypeOf<WasmPlaintext>()
    expectTypeOf<null>().toMatchTypeOf<WasmPlaintext>()
  })
})
