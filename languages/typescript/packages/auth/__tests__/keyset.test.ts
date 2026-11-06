import { afterEach, describe, expect, it } from 'vitest'

// Runtime coverage for `keysetCreate` / `keysetRewrap` through index.js, on
// both Result arms. The static key backend needs no network, so these run
// with no vendor. The vendor paths are covered by the vendor crates' own
// fixtures; the Rust unit tests in src/keyset.rs cover the option checks.
const { keysetCreate, keysetRewrap } =
  require('../index.js') as typeof import('../index')

const KEY_A = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
const KEY_B = 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8='
const VARS = ['CS_TEST_KEYSET_KEY_A', 'CS_TEST_KEYSET_KEY_B'] as const

afterEach(() => {
  for (const name of VARS) delete process.env[name]
})

describe('keysetCreate', () => {
  it('creates a static keyset record with a generated key', async () => {
    const result = await keysetCreate({
      backend: 'static',
      vendorKey: 'key-a',
      mode: 'derived',
      name: 'users',
    })
    if (result.failure) throw result.failure.error
    expect(result.data.record).toMatch(/^stack-keyset:[A-Za-z0-9_-]+$/)
    expect(result.data).toMatchObject({
      backend: 'static',
      mode: 'derived',
      name: 'users',
      vendorKey: 'key-a',
    })
    expect(result.data.keysetId).toMatch(/^[0-9a-f-]{36}$/)
    expect(
      Buffer.from(result.data.generatedStaticKey ?? '', 'base64'),
    ).toHaveLength(32)
  })

  it('reads a static key from the named environment variable', async () => {
    process.env.CS_TEST_KEYSET_KEY_A = KEY_A
    const result = await keysetCreate({
      backend: 'static',
      vendorKey: 'key-a',
      mode: 'derived',
      staticKeyEnv: 'CS_TEST_KEYSET_KEY_A',
    })
    if (result.failure) throw result.failure.error
    expect(result.data.generatedStaticKey).toBeUndefined()
    expect(result.data.name).toBeUndefined()
  })

  it('returns a failure, not a throw, for wrapped data keys on static', async () => {
    const result = await keysetCreate({
      backend: 'static',
      vendorKey: 'key-a',
      mode: 'wrapped',
    })
    expect(result.data).toBeUndefined()
    expect(result.failure?.type).toBe('INVALID_RECORD')
    expect(result.failure?.diagnostic).toBe(
      'stack_kms_vendor::mode_unsupported',
    )
    expect(result.failure?.error).toBeInstanceOf(Error)
  })

  it('returns INVALID_OPTIONS for an unknown backend', async () => {
    const result = await keysetCreate({
      backend: 'zerokms',
      vendorKey: 'k',
      mode: 'derived',
    })
    expect(result.failure?.type).toBe('INVALID_OPTIONS')
    expect(result.failure?.error.message).toContain(
      'aws, gcp, azure, vault, static',
    )
  })
})

describe('keysetRewrap', () => {
  it('moves a static record to another key, keeping its id and name', async () => {
    process.env.CS_TEST_KEYSET_KEY_A = KEY_A
    process.env.CS_TEST_KEYSET_KEY_B = KEY_B
    const created = await keysetCreate({
      backend: 'static',
      vendorKey: 'key-a',
      mode: 'derived',
      name: 'users',
      staticKeyEnv: 'CS_TEST_KEYSET_KEY_A',
    })
    if (created.failure) throw created.failure.error

    const rewrapped = await keysetRewrap({
      record: created.data.record,
      vendorKey: 'key-b',
      staticKeyEnv: 'CS_TEST_KEYSET_KEY_A',
      newStaticKeyEnv: 'CS_TEST_KEYSET_KEY_B',
    })
    if (rewrapped.failure) throw rewrapped.failure.error
    expect(rewrapped.data).toMatchObject({
      keysetId: created.data.keysetId,
      name: 'users',
      vendorKey: 'key-b',
    })

    // The old key no longer opens it.
    const wrong = await keysetRewrap({
      record: rewrapped.data.record,
      staticKeyEnv: 'CS_TEST_KEYSET_KEY_A',
    })
    expect(wrong.failure?.type).toBe('VENDOR_ERROR')
    expect(wrong.failure?.kind).toBe('InvalidCiphertext')
  })

  it('returns INVALID_RECORD for text that is not a record', async () => {
    const result = await keysetRewrap({ record: 'nope' })
    expect(result.failure?.type).toBe('INVALID_RECORD')
    expect(result.failure?.help).toContain('stash keyset create')
  })
})
