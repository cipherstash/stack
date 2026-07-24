/**
 * Runtime parity between the two clients `Encryption` can return.
 *
 * `Encryption` decides its return value with two discriminators that can
 * disagree: overload resolution reads the `config` argument, while the runtime
 * reads the `schemas` argument (`encryption/index.ts`, the `isV3Only &&
 * eqlVersion === 3` branch). Hoisting a config into a `ClientConfig`-typed
 * variable is enough to split them — `ClientConfig.eqlVersion` is `2 | 3`, which
 * is not assignable to the v3 overload's `eqlVersion?: 3`, so the call selects
 * the NOMINAL overload while the runtime still hands back the TYPED client.
 *
 * No type-level design closes that: the runtime inspects values, the type
 * inspects a static type that can be widened away. It ends when the EQL v2
 * removal collapses the two clients into one (#637). Until then the mismatch
 * must not be able to crash, which means every member of `EncryptionClient` has
 * to exist on the typed client at runtime.
 */
import { describe, expect, it, vi } from 'vitest'
import { Encryption, EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/encryption/v3'
import type { ClientConfig } from '@/types'

const users = encryptedTable('users', { email: types.TextSearch('email') })

/**
 * Build a client without credentials by stubbing `init` to resolve to itself —
 * `Encryption` only needs a successful `Result` to reach its return branch.
 */
async function buildWithStubbedInit(config: ClientConfig) {
  const spy = vi
    .spyOn(EncryptionClient.prototype, 'init')
    .mockImplementation(async function (this: EncryptionClient) {
      return { data: this }
    } as never)
  try {
    return await Encryption({ schemas: [users], config })
  } finally {
    spy.mockRestore()
  }
}

describe('typed client / nominal client runtime parity', () => {
  it('a ClientConfig-typed variable types as nominal but returns the typed client', async () => {
    const config: ClientConfig = {}
    const client = await buildWithStubbedInit(config)

    // The static type here is `EncryptionClient`. The runtime disagrees.
    expect('encryptQuery' in client).toBe(true)
    expect(client).not.toBeInstanceOf(EncryptionClient)
  })

  it('exposes every EncryptionClient member, so the mismatch cannot crash', async () => {
    const config: ClientConfig = {}
    const client = await buildWithStubbedInit(config)

    const nominalMembers = Object.getOwnPropertyNames(
      EncryptionClient.prototype,
    ).filter((name) => name !== 'constructor')

    // `init` was the only member missing, which turned the type/runtime
    // mismatch above into `TypeError: client.init is not a function` for
    // anything holding the client through its declared `EncryptionClient` type.
    const missing = nominalMembers.filter(
      (name) => typeof (client as Record<string, unknown>)[name] !== 'function',
    )
    expect(missing).toEqual([])
  })

  it('delegates init to the underlying client', async () => {
    const config: ClientConfig = {}
    const client = await buildWithStubbedInit(config)

    const spy = vi
      .spyOn(EncryptionClient.prototype, 'init')
      .mockResolvedValue({ data: {} } as never)

    await (client as unknown as EncryptionClient).init({} as never)
    expect(spy).toHaveBeenCalledTimes(1)

    spy.mockRestore()
  })
})
