import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  decrypt,
  decryptBulk,
  encrypt,
  encryptBulk,
  newClient,
} from '@cipherstash/protect-ffi'

import { datesConfig } from './common.js'

// Dates cross the FFI boundary as ISO 8601 strings (a JSON limitation — there
// is no native Date type in JSON). Callers who have a JS `Date` pass
// `d.toISOString()`; decrypt returns an ISO string which the caller can wrap
// in `new Date(...)` to get a `Date` back.

describe('Date / Timestamp encrypt + decrypt', () => {
  test('round-trips a Date (as ISO string) through a timestamp column', async () => {
    const client = await newClient({ encryptConfig: datesConfig })
    const d = new Date('2025-03-14T12:34:56.789Z')

    const ciphertext = await encrypt(client, {
      plaintext: d.toISOString(),
      table: 'events',
      column: 'occurred_at',
    })

    const decrypted = await decrypt(client, { ciphertext })

    expect(typeof decrypted).toBe('string')
    expect(new Date(decrypted as string).toISOString()).toBe(d.toISOString())
  })

  test('round-trips through a date column (time truncated)', async () => {
    const client = await newClient({ encryptConfig: datesConfig })
    const d = new Date('2025-03-14T12:34:56.789Z')

    const ciphertext = await encrypt(client, {
      plaintext: d.toISOString(),
      table: 'events',
      column: 'occurred_on',
    })

    const decrypted = await decrypt(client, { ciphertext })

    expect(typeof decrypted).toBe('string')
    // date column stores day-precision; the value comes back as UTC midnight.
    expect(new Date(decrypted as string).toISOString()).toBe(
      '2025-03-14T00:00:00.000Z',
    )
  })

  test('accepts YYYY-MM-DD for a date column', async () => {
    const client = await newClient({ encryptConfig: datesConfig })

    const ciphertext = await encrypt(client, {
      plaintext: '2025-03-14',
      table: 'events',
      column: 'occurred_on',
    })

    const decrypted = await decrypt(client, { ciphertext })

    expect(new Date(decrypted as string).toISOString()).toBe(
      '2025-03-14T00:00:00.000Z',
    )
  })

  test('bulk encrypt/decrypt preserves timestamp values', async () => {
    const client = await newClient({ encryptConfig: datesConfig })
    const a = new Date('2024-01-02T03:04:05.000Z')
    const b = new Date('2025-06-07T08:09:10.500Z')

    const ciphertexts = await encryptBulk(client, {
      plaintexts: [
        { plaintext: a.toISOString(), table: 'events', column: 'occurred_at' },
        { plaintext: b.toISOString(), table: 'events', column: 'occurred_at' },
      ],
    })

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((c) => ({ ciphertext: c })),
    })

    expect(decrypted).toHaveLength(2)
    expect(new Date(decrypted[0] as string).toISOString()).toBe(a.toISOString())
    expect(new Date(decrypted[1] as string).toISOString()).toBe(b.toISOString())
  })

  test('rejects an unparseable string for a date column', async () => {
    const client = await newClient({ encryptConfig: datesConfig })
    await expect(
      encrypt(client, {
        plaintext: 'not a date',
        table: 'events',
        column: 'occurred_on',
      }),
    ).rejects.toThrowError()
  })
})
