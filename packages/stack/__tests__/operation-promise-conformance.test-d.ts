import type { Result } from '@byteslice/result'
import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptionOperation } from '@/encryption/operations/base-operation'
import type { EncryptionError } from '@/errors'
import type { Encrypted } from '@/types'

/**
 * Pins the guarantee stage 2 of #798 exists to create: an operation is
 * assignable wherever a `Promise` was.
 *
 * This is what makes the WASM entry able to return operations instead of bare
 * `Promise<WasmResult<T>>` WITHOUT a breaking change. If someone removes
 * `catch`, `finally`, or `[Symbol.toStringTag]` from `EncryptionOperation` —
 * or narrows `then` — the class stops satisfying `Promise<…>` structurally,
 * that adoption silently becomes breaking, and nothing else in the suite
 * would notice, because every runtime test only ever awaits.
 */
type Op = EncryptionOperation<Encrypted>
type Resolved = Result<Encrypted, EncryptionError>

describe('EncryptionOperation satisfies Promise structurally (#798)', () => {
  it('is assignable to Promise<Result<…>>', () => {
    expectTypeOf<Op>().toMatchTypeOf<Promise<Resolved>>()
  })

  it('awaits to a Result, not to the bare value', () => {
    expectTypeOf<Awaited<Op>>().toEqualTypeOf<Resolved>()
  })

  it('carries the three members `then` alone does not provide', () => {
    expectTypeOf<Op>().toHaveProperty('catch')
    expectTypeOf<Op>().toHaveProperty('finally')
    expectTypeOf<Op>().toHaveProperty(Symbol.toStringTag)
  })

  it('survives Promise.all, which resolves each to its Result', async () => {
    expectTypeOf<
      Awaited<ReturnType<typeof Promise.all<[Op, Op]>>>
    >().toEqualTypeOf<[Resolved, Resolved]>()
  })
})
