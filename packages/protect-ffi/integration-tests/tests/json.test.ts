import 'dotenv/config'
import {
  type Identifier,
  decrypt,
  encrypt,
  newClient,
} from '@cipherstash/protect-ffi'
import { describe, expect, test } from 'vitest'

// Import shared encryptConfig from common.js
import { assertSteVec, jsonOpaque, jsonSteVec } from './common.js'

type UserColumn = Identifier<typeof jsonOpaque>

const userProfile: UserColumn = {
  table: 'users',
  column: 'profile',
}

// There are 2 ways we might want to handle JSON data:
// 1. As an opaque blob - we don't care about the structure of the data, we just
//    want to store and retrieve it as-is.
// 2. As a structured object - we want to be able to query and index the data,
//    so we need to know the structure of the data.
//
// In this test suite, we'll test both options.
describe.each([
  { encryptConfig: jsonOpaque, description: 'opaque' },
  { encryptConfig: jsonSteVec, description: 'ste_vec' },
])(
  'Can round-trip encrypt & decrypt JSON',
  ({ encryptConfig, description }) => {
    describe(`using ${description} config`, () => {
      test('object', async ({ annotate }) => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: 123 }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('array', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = [1, 2, 3]

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('nested array within object', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: [1, 2, 3] }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('nested object within object', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: { qux: 'quux' } }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })

      test('nested object within array', async () => {
        const client = await newClient({ encryptConfig })
        const originalPlaintext = { foo: 'bar', baz: [{ qux: 'quux' }] }

        const ciphertext = await encrypt(client, {
          plaintext: originalPlaintext,
          ...userProfile,
        })

        const decrypted = await decrypt(client, { ciphertext })

        expect(decrypted).toEqual(originalPlaintext)
      })
    })
  },
)

describe('SteVec output structure', () => {
  test('encrypted output has expected fields', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const ciphertext = await encrypt(client, {
      plaintext: { foo: 'bar' },
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(ciphertext).toHaveProperty('sv')
    expect(ciphertext).toHaveProperty('i')
    expect(ciphertext).toHaveProperty('v')
    expect(ciphertext).toHaveProperty('h')
    // EQL v3 places raw root ciphertext at sv[0].c and key material in h.
    expect(ciphertext).not.toHaveProperty('c')

    // Validate entry structure uses new field names
    expect(Array.isArray(ciphertext.sv)).toBe(true)
    expect(ciphertext.sv?.length ?? 0).toBeGreaterThan(0)

    const entry = ciphertext.sv?.[0]
    expect(entry).toHaveProperty('c') // Entry ciphertext (new format)
    expect(entry).toHaveProperty('s') // Tokenized selector

    // Old field names should NOT exist
    expect(entry).not.toHaveProperty('tokenized_selector')
    expect(entry).not.toHaveProperty('term')
    expect(entry).not.toHaveProperty('record')
    expect(entry).not.toHaveProperty('parent_is_array')
  })
})

describe('SteVec index field generation', () => {
  describe('selector field (s)', () => {
    test('should include selector field for entries', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test' },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      // At least one entry should have a selector
      const entriesWithSelector = sv.filter((e) => e.s !== undefined)
      expect(entriesWithSelector.length).toBeGreaterThan(0)

      // Selector should be hex encoded
      for (const entry of entriesWithSelector) {
        expect(entry.s).toMatch(/^[0-9a-f]+$/i)
      }
    })
  })

  describe('array flag (a)', () => {
    test('should not set array flag when array_index_mode is default (NONE)', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { items: ['apple', 'banana', 'cherry'] },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      // With default ArrayIndexMode (NONE), array items should not have a: true
      const arrayEntries = sv.filter((e) => e.a === true)
      expect(arrayEntries.length).toBe(0)
    })

    test('should not set array flag for non-array elements', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test', count: 42 },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()

      // Non-array items should not have a: true
      for (const entry of ciphertext.sv ?? []) {
        expect(entry.a).not.toBe(true)
      }
    })
  })

  // EQL v3 uses the Compat-mode `op` term for ordering string and number path
  // entries. Exact equality for every JSON scalar is selector presence, so
  // entries do not carry `hm`.
  describe('OPE index field (op)', () => {
    test('should include OPE field (op) for numeric values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { count: 42, price: 99.99 },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      const entriesWithOpe = sv.filter((e) => e.op !== undefined)
      expect(entriesWithOpe.length).toBeGreaterThan(0)

      for (const entry of entriesWithOpe) {
        expect(entry.op).toMatch(/^[0-9a-f]+$/i)
      }

      expect(sv.filter((e) => e.oc !== undefined)).toHaveLength(0)
    })

    test('should include OPE field (op) for string values', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'alice', city: 'london' },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      const entriesWithOpe = sv.filter((e) => e.op !== undefined)
      expect(entriesWithOpe.length).toBeGreaterThan(0)

      for (const entry of entriesWithOpe) {
        expect(entry.op).toMatch(/^[0-9a-f]+$/i)
      }

      expect(sv.filter((e) => e.oc !== undefined)).toHaveLength(0)
    })
  })

  describe('value-inclusive selector entries', () => {
    test('the root object has a term-less selector entry', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { name: 'test', email: 'test@example.com' },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      expect(sv[0]).toHaveProperty('s')
      expect(sv[0].hm).toBeUndefined()
      expect(sv[0].op).toBeUndefined()
    })

    test('boolean exact-match entries carry selectors without HMAC terms', async () => {
      const client = await newClient({ encryptConfig: jsonSteVec })

      const ciphertext = await encrypt(client, {
        plaintext: { active: true, verified: false },
        table: 'users',
        column: 'profile',
      })

      assertSteVec(ciphertext)
      expect(ciphertext.sv).toBeDefined()
      const sv = ciphertext.sv ?? []

      expect(sv.filter((e) => e.hm !== undefined)).toHaveLength(0)
      expect(sv.filter((e) => e.op === undefined).length).toBeGreaterThan(0)
    })
  })
})

describe('deeply nested JSON encryption', () => {
  test('should handle 4 levels of object nesting', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const deepNested = {
      level1: {
        level2: {
          level3: {
            level4: 'deep value',
          },
        },
      },
    }

    const ciphertext = await encrypt(client, {
      plaintext: deepNested,
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(Array.isArray(ciphertext.sv)).toBe(true)
    expect(ciphertext.sv?.length).toBeGreaterThan(0)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(deepNested)
  })

  test('should handle arrays nested within objects within arrays', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const complexNested = {
      items: [{ tags: ['tag1', 'tag2'] }, { tags: ['tag3', 'tag4', 'tag5'] }],
    }

    const ciphertext = await encrypt(client, {
      plaintext: complexNested,
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(Array.isArray(ciphertext.sv)).toBe(true)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(complexNested)
  })

  test('should handle mixed deep nesting with various types', async () => {
    const client = await newClient({ encryptConfig: jsonSteVec })

    const mixedDeep = {
      user: {
        profile: {
          settings: {
            notifications: true,
            theme: 'dark',
            limits: [10, 20, 30],
          },
        },
        scores: [100, 200, 300],
      },
      metadata: {
        version: 1,
      },
    }

    const ciphertext = await encrypt(client, {
      plaintext: mixedDeep,
      table: 'users',
      column: 'profile',
    })

    assertSteVec(ciphertext)
    expect(ciphertext.sv).toBeDefined()
    expect(Array.isArray(ciphertext.sv)).toBe(true)
    expect(ciphertext.sv?.length).toBeGreaterThan(0)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(mixedDeep)
  })
})

// JSON plaintexts follow JSON.stringify semantics at the boundary on BOTH
// platforms: on Neon because neon's `Json` extractor stringifies the
// options object, on wasm because the boundary canonicalizes plaintexts
// through JSON.stringify → JSON.parse explicitly (see the wasm suite's
// counterpart test in wasm-round-trip.test.ts). This block pins the Neon
// half of that contract.
describe('json plaintext boundary', () => {
  test('rejects a bigint nested inside a json plaintext with a TypeError', async () => {
    const client = await newClient({ encryptConfig: jsonOpaque })

    // JSON has no bigint — JSON.stringify throws, and the error reaches
    // the caller as the engine's own TypeError (normalizeError passes
    // unknown error classes through untouched).
    await expect(
      encrypt(client, {
        plaintext: { count: 2n ** 60n + 1n },
        ...userProfile,
      }),
    ).rejects.toThrow(TypeError)
  })
})
