/**
 * Where the compile-time non-emptiness guard stops, and the runtime one starts.
 *
 * A-4 widened `Encryption`'s v3 overload from a non-empty TUPLE to any array,
 * moving the guard onto the `schemas` property via
 * `NonEmptyV3<S> = S['length'] extends 0 ? never : S`. That guard fires only
 * when the argument's TYPE has a statically known length of `0`. Once the type
 * widens to `AnyV3Table[]` — a shared module export, a push-built array, a
 * `.filter()` result, or a spread of any of those — `S['length']` is `number`,
 * `number extends 0` is false, and the call compiles no matter how many tables
 * are actually in it.
 *
 * So the widening deliberately traded a compile error for a runtime one on
 * exactly the forms it exists to enable. `skills/stash-encryption` documents
 * that boundary, and this pins the runtime half of it: the guard must reject an
 * empty set BEFORE any FFI client is constructed, on every entry point.
 *
 * The compile-time half is pinned in `encryption-overloads.test-d.ts`.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AnyV3Table } from '@/eql/v3'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'

vi.mock('@cipherstash/protect-ffi', () => ({
  newClient: vi.fn(async () => ({ __mock: 'client' })),
}))

import * as ffi from '@cipherstash/protect-ffi'

const EMPTY_SCHEMAS = /At least one encryptedTable must be provided/

beforeEach(() => {
  vi.clearAllMocks()
})

describe('empty schema sets are refused at runtime', () => {
  // The forms below all COMPILE — that is the point. Each is a shape the A-4
  // widening admits, and each is empty at runtime.
  it('rejects a shared array annotated AnyV3Table[] that is empty', async () => {
    const shared: AnyV3Table[] = []

    await expect(Encryption({ schemas: shared })).rejects.toThrow(EMPTY_SCHEMAS)
  })

  it('rejects a ReadonlyArray that is empty', async () => {
    const frozen: ReadonlyArray<AnyV3Table> = []

    await expect(Encryption({ schemas: frozen })).rejects.toThrow(EMPTY_SCHEMAS)
  })

  it('rejects a spread of an empty array — a literal at the call site', async () => {
    // Spreading erases the tuple length, so even an array literal here carries
    // no compile-time non-emptiness. This is the form most likely to be read as
    // "a literal, therefore checked".
    const src: AnyV3Table[] = []

    await expect(Encryption({ schemas: [...src] })).rejects.toThrow(
      EMPTY_SCHEMAS,
    )
  })

  it('rejects an array emptied by a filter', async () => {
    const all: AnyV3Table[] = []

    await expect(
      Encryption({ schemas: all.filter(() => false) }),
    ).rejects.toThrow(EMPTY_SCHEMAS)
  })

  // The v2 builders reach the same guard — it predates the v3 typed client and
  // is not part of the overload machinery.
  it('rejects an empty v2 schema set', async () => {
    const v2: Array<ReturnType<typeof encryptedTable>> = []

    await expect(Encryption({ schemas: v2 })).rejects.toThrow(EMPTY_SCHEMAS)
  })

  it('refuses before constructing the FFI client, so no credentials are needed', async () => {
    const shared: AnyV3Table[] = []

    await expect(Encryption({ schemas: shared })).rejects.toThrow(EMPTY_SCHEMAS)
    expect(ffi.newClient).not.toHaveBeenCalled()
  })

  // Control: the same call shape with one table gets past the guard, proving the
  // assertions above fail on emptiness rather than on the array form itself.
  it('accepts a non-empty array of the same widened type', async () => {
    const shared: AnyV3Table[] = []
    shared.push(
      encryptedTable('users', {
        email: encryptedColumn('email'),
      }) as unknown as AnyV3Table,
    )

    await expect(Encryption({ schemas: shared })).resolves.toBeDefined()
    expect(ffi.newClient).toHaveBeenCalledTimes(1)
  })
})
