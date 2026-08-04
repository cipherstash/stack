import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type Identifier,
  decrypt,
  encrypt,
  isEncrypted,
  newClient,
} from '@cipherstash/protect-ffi'

// Import shared configs from common.js
import {
  assertScalar,
  assertSteVec,
  scalarConfig as encryptConfig,
  jsonSteVec,
} from './common.js'

type UserColumn = Identifier<typeof encryptConfig>

const stringColumn: UserColumn = {
  table: 'users',
  column: 'email',
}

const bigintColumn: UserColumn = {
  table: 'users',
  column: 'score',
}

const numberColumn: UserColumn = {
  table: 'users',
  column: 'score_float',
}

const cases: {
  identifier: UserColumn
  plaintext: string | number | bigint
  /**
   * What decrypt returns. Differs from the input for the bigint column:
   * cast_as 'bigint' ALWAYS decrypts to a JS bigint (breaking change —
   * it used to come back as a number).
   */
  expected: string | number | bigint
}[] = [
  { identifier: stringColumn, plaintext: 'abc', expected: 'abc' },
  { identifier: bigintColumn, plaintext: 123, expected: 123n },
  { identifier: bigintColumn, plaintext: 456n, expected: 456n },
  { identifier: numberColumn, plaintext: 123.456, expected: 123.456 },
]

describe.each(cases)(
  'encrypt and decrypt',
  ({ identifier, plaintext, expected }) => {
    describe(`using column ${identifier.column} with ${typeof plaintext} value`, () => {
      test('can round-trip encrypt and decrypt a string', async () => {
        const client = await newClient({ encryptConfig })
        const ciphertext = await encrypt(client, {
          plaintext,
          ...identifier,
        })

        expect(isEncrypted(ciphertext)).toBe(true)

        const decrypted = await decrypt(client, { ciphertext })
        expect(decrypted).toBe(expected)
      })

      test('can explicitly pass in undefined for optional fields', async () => {
        const client = await newClient({ encryptConfig })

        const ciphertext = await encrypt(client, {
          plaintext,
          lockContext: undefined,
          unverifiedContext: undefined,
          ...identifier,
        })

        const decrypted = await decrypt(client, {
          ciphertext,
          lockContext: undefined,
          unverifiedContext: undefined,
        })

        expect(decrypted).toBe(expected)
      })
    })
  },
)

describe('bigint plaintexts', () => {
  const I64_MAX = 2n ** 63n - 1n
  const I64_MIN = -(2n ** 63n)

  test('round-trips the full i64 range exactly as JS bigint', async () => {
    const client = await newClient({ encryptConfig })

    for (const plaintext of [I64_MAX, I64_MIN, 0n, -1n]) {
      const ciphertext = await encrypt(client, {
        plaintext,
        table: 'users',
        column: 'score',
      })
      const decrypted = await decrypt(client, { ciphertext })
      expect(typeof decrypted).toBe('bigint')
      expect(decrypted).toBe(plaintext)
    }
  })

  test('rejects 2^63 (just above i64::MAX) with a RangeError at the boundary', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encrypt(client, {
        plaintext: I64_MAX + 1n,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrowError(RangeError)
    await expect(
      encrypt(client, {
        plaintext: I64_MAX + 1n,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrowError(/above the maximum.*signed 64-bit integer/)
  })

  test('rejects -(2^63) - 1 (just below i64::MIN) with a RangeError at the boundary', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encrypt(client, {
        plaintext: I64_MIN - 1n,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrowError(/below the minimum.*signed 64-bit integer/)
  })

  test('number input beyond the i64 range is still rejected (existing guard)', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encrypt(client, {
        plaintext: 1e19,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrowError(/out of range/)
  })
})

describe('coercion', () => {
  test('encrypting a float as an integer errors instead of truncating', async () => {
    // Truncation would silently corrupt the stored value AND the index
    // terms derived from it, so any value with a fractional component is
    // rejected rather than coerced (likewise NaN/Infinity/out-of-range).
    const client = await newClient({ encryptConfig })

    const floatValue = 123.987

    await expect(
      encrypt(client, {
        plaintext: floatValue,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrowError(/fractional component/)
  })

  test('encrypting an integer as a float will preserve the value', async () => {
    const client = await newClient({ encryptConfig })

    const intValue = 123
    const expectedFloatValue = 123.0

    const ciphertext = await encrypt(client, {
      plaintext: intValue,
      table: 'users',
      column: 'score_float',
    })

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toBe(expectedFloatValue)
  })

  test('encrypting a string as an integer will error', async () => {
    const client = await newClient({ encryptConfig })

    const stringValue = 'not-a-number'

    await expect(
      encrypt(client, {
        plaintext: stringValue,
        table: 'users',
        column: 'score',
      }),
    ).rejects.toThrowError()
  })

  test('encrypting a string as a float will error', async () => {
    const client = await newClient({ encryptConfig })

    const stringValue = 'not-a-number'

    await expect(
      encrypt(client, {
        plaintext: stringValue,
        table: 'users',
        column: 'score_float',
      }),
    ).rejects.toThrowError()
  })
})

describe('isEncrypted validation', () => {
  test('should return false when v field is missing', () => {
    const missingVersion = {
      i: { t: 'users', c: 'email' },
      c: 'somedata',
    }

    // biome-ignore lint/suspicious/noExplicitAny: Testing invalid data intentionally
    expect(isEncrypted(missingVersion as any)).toBe(false)
  })

  test('should return false when i field is missing', () => {
    const missingIdentifier = {
      v: 1,
      c: 'somedata',
    }

    // biome-ignore lint/suspicious/noExplicitAny: Testing invalid data intentionally
    expect(isEncrypted(missingIdentifier as any)).toBe(false)
  })
})

describe('EQL v2.3 wire format', () => {
  test('scalar storage payload carries k:"ct" discriminator', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email',
    })

    expect((ciphertext as { k?: string }).k).toBe('ct')
    expect(ciphertext).toHaveProperty('c')
    expect(ciphertext).toHaveProperty('i')
    expect(ciphertext).toHaveProperty('v')
  })

  test('SteVec storage payload carries k:"sv" discriminator', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const ciphertext = await encrypt(client, {
      plaintext: { foo: 'bar' },
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext).toHaveProperty('sv')
    // SteVec payloads place the root ciphertext at sv[0].c, not at the root.
    expect(ciphertext).not.toHaveProperty('c')
    expect(ciphertext.sv?.[0]).toHaveProperty('c')
  })
})

describe('encrypted output SEM fields', () => {
  test('should include hm field when unique index configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email', // has unique: {} index
    })

    assertScalar(ciphertext)
    // hm = HMAC for exact match queries
    expect(ciphertext.hm).toBeDefined()
    expect(typeof ciphertext.hm).toBe('string')
    expect(ciphertext.hm?.length).toBeGreaterThan(0)
  })

  test('should include ob field when ore index configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 100,
      table: 'users',
      column: 'score', // has ore: {} index
    })

    assertScalar(ciphertext)
    // ob = ORE blocks for range queries
    expect(ciphertext.ob).toBeDefined()
    expect(Array.isArray(ciphertext.ob)).toBe(true)
    expect(ciphertext.ob?.length).toBeGreaterThan(0)
  })

  test('should include bf field when match index configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email', // has match: {} index
    })

    assertScalar(ciphertext)
    // bf = bloom filter for fuzzy/substring match queries
    expect(ciphertext.bf).toBeDefined()
    expect(Array.isArray(ciphertext.bf)).toBe(true)
    expect(ciphertext.bf?.length).toBeGreaterThan(0)
  })

  test('should include multiple SEM fields when multiple indexes configured', async () => {
    const client = await newClient({ encryptConfig })

    const ciphertext = await encrypt(client, {
      plaintext: 'test@example.com',
      table: 'users',
      column: 'email', // has ore, match, and unique indexes
    })

    assertScalar(ciphertext)
    // email column has all three index types
    expect(ciphertext.hm).toBeDefined() // unique
    expect(ciphertext.ob).toBeDefined() // ore
    expect(ciphertext.bf).toBeDefined() // match
  })
})
