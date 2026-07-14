/**
 * Behavioural tests for the v3 `EncryptedNumber` envelope.
 *
 * Mirrors `test/envelope-double.test.ts` (subclass surface, decrypt
 * round-trip, the four non-`toJSON` redaction overrides, the
 * `JSON.stringify` placeholder shape) and additionally pins the
 * sibling relationship with the v2 `EncryptedDouble`: the two classes
 * must not satisfy each other's `instanceof` (a cross-version leak).
 */

import { inspect } from 'node:util'
import { describe, expect, it, vi } from 'vitest'
import { EncryptedEnvelopeBase } from '../../src/execution/envelope-base'
import { EncryptedDouble } from '../../src/execution/envelope-double'
import type { CipherstashSdk } from '../../src/execution/sdk'
import { EncryptedNumber } from '../../src/v3/envelope-number'

function emptySdk(): CipherstashSdk {
  return {
    decrypt: vi.fn(),
    bulkEncrypt: vi.fn(),
    bulkDecrypt: vi.fn(),
  }
}

describe('EncryptedNumber — sibling of EncryptedDouble', () => {
  it('is a distinct sibling of EncryptedDouble (no cross-instanceof leak)', () => {
    const n = EncryptedNumber.from(42)
    expect(n).toBeInstanceOf(EncryptedNumber)
    expect(n instanceof EncryptedDouble).toBe(false)
    expect(EncryptedDouble.from(42) instanceof EncryptedNumber).toBe(false)
  })

  it('renders the $encryptedNumber placeholder marker (distinct typeName)', () => {
    expect(JSON.stringify(EncryptedNumber.from(7))).toBe(
      '{"$encryptedNumber":"<opaque>"}',
    )
  })
})

describe('EncryptedNumber.from(plaintext)', () => {
  it('returns an EncryptedNumber instance that extends EncryptedEnvelopeBase', () => {
    const envelope = EncryptedNumber.from(3.14)
    expect(envelope).toBeInstanceOf(EncryptedNumber)
    expect(envelope).toBeInstanceOf(EncryptedEnvelopeBase)
  })

  it('redacts and round-trips plaintext via decrypt() fast path', async () => {
    const envelope = EncryptedNumber.from(3.14)
    expect(String(envelope)).toBe('[REDACTED]')
    await expect(envelope.decrypt()).resolves.toBe(3.14)
  })

  it('preserves negative and zero values without coercion', async () => {
    await expect(EncryptedNumber.from(-1.5).decrypt()).resolves.toBe(-1.5)
    await expect(EncryptedNumber.from(0).decrypt()).resolves.toBe(0)
  })
})

describe('EncryptedNumber.fromInternal(...) — read-side round-trip', () => {
  it('decrypt({signal}) calls the SDK single-cell decrypt and returns the numeric plaintext', async () => {
    const ciphertext = { c: 'cipher', i: { t: 'metric', c: 'value' } }
    const decryptMock = vi.fn().mockResolvedValue(42.5)
    const sdk: CipherstashSdk = {
      decrypt: decryptMock,
      bulkEncrypt: vi.fn(),
      bulkDecrypt: vi.fn(),
    }

    const envelope = EncryptedNumber.fromInternal({
      ciphertext,
      table: 'metric',
      column: 'value',
      sdk,
    })

    const ac = new AbortController()
    const result = await envelope.decrypt({ signal: ac.signal })

    expect(result).toBe(42.5)
    expect(decryptMock).toHaveBeenCalledTimes(1)
    expect(decryptMock.mock.calls[0]?.[0]).toMatchObject({
      ciphertext,
      table: 'metric',
      column: 'value',
      signal: ac.signal,
    })
  })

  it('exposes the (table, column) routing context + SDK on the handle', () => {
    const sdk = emptySdk()
    const envelope = EncryptedNumber.fromInternal({
      ciphertext: 'wire',
      table: 'metric',
      column: 'value',
      sdk,
    })
    const handle = envelope.expose()
    expect(handle.table).toBe('metric')
    expect(handle.column).toBe('value')
    expect(handle.sdk).toBe(sdk)
    expect(handle.plaintext).toBeUndefined()
  })
})

describe('EncryptedNumber — accidental-exposure overrides', () => {
  it('toString() returns [REDACTED] regardless of plaintext value', () => {
    expect(EncryptedNumber.from(42).toString()).toBe('[REDACTED]')
  })

  it('valueOf() returns [REDACTED]', () => {
    expect(EncryptedNumber.from(42).valueOf()).toBe('[REDACTED]')
  })

  it('Symbol.toPrimitive returns [REDACTED] for template-literal coercion', () => {
    const envelope = EncryptedNumber.from(42)
    expect(`v=${envelope}`).toBe('v=[REDACTED]')
  })

  it('util.inspect returns [REDACTED]', () => {
    const envelope = EncryptedNumber.from(42)
    const inspected = inspect(envelope, {
      depth: Number.POSITIVE_INFINITY,
      getters: true,
    })
    expect(inspected).not.toContain('42')
    expect(inspected).toContain('[REDACTED]')
  })

  it('JSON.stringify cannot leak plaintext', () => {
    const envelope = EncryptedNumber.from(123.456789)
    const json = JSON.stringify({ value: envelope })
    expect(json).not.toContain('123.456789')
  })
})
