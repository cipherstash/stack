/**
 * Behavioural tests for the v3 cell codec + per-domain runtime
 * descriptors.
 *
 * Pins:
 *   - one descriptor per catalog domain, keyed by the GA codec id
 *     (`cipherstash/eql-v3/eql_v3_*@1`) with the concrete
 *     `public.eql_v3_*` domain as native/target type — NOT the shared
 *     v2 `eql_v2_encrypted` composite;
 *   - traits derived from the domain's query capabilities
 *     (`v3TraitsForCapabilities`), including `cipherstash:searchable-json`
 *     for the json domain;
 *   - per-castAs envelope rendering (`EncryptedNumber` for number
 *     domains, `EncryptedBigInt` for bigint, `EncryptedJson` for json);
 *   - encode/decode over the plain-JSONB v3 wire, never the v2
 *     composite literal.
 */

import type { CodecInstanceContext } from '@prisma-next/framework-components/codec'
import type { SqlCodecCallContext } from '@prisma-next/sql-relational-core/ast'
import { describe, expect, it, vi } from 'vitest'
import { EncryptedBigInt } from '../../src/execution/envelope-bigint'
import { EncryptedJson } from '../../src/execution/envelope-json'
import { EncryptedString } from '../../src/execution/envelope-string'
import type { CipherstashSdk } from '../../src/execution/sdk'
import { bulkEncryptMiddlewareV3 } from '../../src/v3/bulk-encrypt-v3'
import { V3_CODEC_IDS } from '../../src/v3/catalog'
import { createV3CodecDescriptors } from '../../src/v3/codec-runtime-v3'
import { EncryptedNumber } from '../../src/v3/envelope-number'

const emptySdk = (): CipherstashSdk => ({
  decrypt: vi.fn(),
  bulkEncrypt: vi.fn(),
  bulkDecrypt: vi.fn(),
})

const instanceCtx = {} as CodecInstanceContext

function codecFor(
  descriptors: ReturnType<typeof createV3CodecDescriptors>,
  codecId: string,
) {
  const descriptor = descriptors.find((d) => d.codecId === codecId)
  if (!descriptor) throw new Error(`no descriptor for ${codecId}`)
  return descriptor.factory({
    castAs: 'string',
    capabilities: {},
  })(instanceCtx)
}

describe('createV3CodecDescriptors — descriptor metadata', () => {
  it('emits one descriptor per catalog domain, keyed by the GA codec id set', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    expect(ds.map((d) => d.codecId).sort()).toEqual([...V3_CODEC_IDS].sort())
  })

  it('native type = the concrete public.eql_v3_* domain (never eql_v2_encrypted)', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const textSearch = ds.find(
      (d) => d.codecId === 'cipherstash/eql-v3/eql_v3_text_search@1',
    )
    expect(textSearch).toBeDefined()
    expect(textSearch?.targetTypes).toEqual(['public.eql_v3_text_search'])
    expect(textSearch?.meta).toEqual({
      db: { sql: { postgres: { nativeType: 'public.eql_v3_text_search' } } },
    })
    expect(textSearch?.isParameterized).toBe(true)
    for (const d of ds) {
      expect(d.targetTypes).toHaveLength(1)
      expect(d.targetTypes[0]).toMatch(/^public\.eql_v3_/)
      expect(d.targetTypes[0]).not.toBe('eql_v2_encrypted')
    }
  })

  it('storage-only eql_v3_boolean declares no traits; eql_v3_text_search declares all three', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    expect(
      ds.find((d) => d.codecId === 'cipherstash/eql-v3/eql_v3_boolean@1')
        ?.traits,
    ).toEqual([])
    expect(
      [
        ...(ds.find(
          (d) => d.codecId === 'cipherstash/eql-v3/eql_v3_text_search@1',
        )?.traits ?? []),
      ].sort(),
    ).toEqual([
      'cipherstash:equality',
      'cipherstash:free-text-search',
      'cipherstash:order-and-range',
    ])
  })

  it('eql_v3_json_search declares only the searchable-json trait', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    expect(
      ds.find((d) => d.codecId === 'cipherstash/eql-v3/eql_v3_json_search@1')
        ?.traits,
    ).toEqual(['cipherstash:searchable-json'])
  })

  it('renderOutputType maps castAs to the envelope class name', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const render = (codecId: string) =>
      ds
        .find((d) => d.codecId === codecId)
        ?.renderOutputType?.({ castAs: 'string', capabilities: {} })
    expect(render('cipherstash/eql-v3/eql_v3_text_search@1')).toBe(
      'EncryptedString',
    )
    expect(render('cipherstash/eql-v3/eql_v3_integer_ord@1')).toBe(
      'EncryptedNumber',
    )
    expect(render('cipherstash/eql-v3/eql_v3_bigint_ord@1')).toBe(
      'EncryptedBigInt',
    )
    expect(render('cipherstash/eql-v3/eql_v3_date_eq@1')).toBe('EncryptedDate')
    expect(render('cipherstash/eql-v3/eql_v3_timestamp_ord@1')).toBe(
      'EncryptedDate',
    )
    expect(render('cipherstash/eql-v3/eql_v3_boolean@1')).toBe(
      'EncryptedBoolean',
    )
    expect(render('cipherstash/eql-v3/eql_v3_json_search@1')).toBe(
      'EncryptedJson',
    )
  })
})

describe('CipherstashV3CellCodec — encode (plain JSONB)', () => {
  const callCtx = {} as SqlCodecCallContext

  it("serialises an envelope's ciphertext to plain JSONB text", async () => {
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const envelope = EncryptedString.fromInternal({
      ciphertext: { c: 'abc' },
      table: 'users',
      column: 'email',
      sdk: emptySdk(),
    })
    const encoded = await codec.encode(envelope, callCtx)
    expect(encoded).toBe('{"c":"abc"}')
  })

  it('never emits the v2 composite literal shape', async () => {
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const envelope = EncryptedString.fromInternal({
      ciphertext: { c: 'with "quotes"' },
      table: 'users',
      column: 'email',
      sdk: emptySdk(),
    })
    const encoded = await codec.encode(envelope, callCtx)
    // Plain JSON text — not the v2 composite literal `("...")` with its
    // doubled-quote escaping.
    expect(encoded).toBe(JSON.stringify({ c: 'with "quotes"' }))
    expect(encoded as string).not.toMatch(/^\(/)
  })

  it('passes a pre-serialised JSONB string through unchanged (middleware two-pass)', async () => {
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    expect(await codec.encode('{"c":"enc"}', callCtx)).toBe('{"c":"enc"}')
  })

  it('returns the envelope unchanged when it has no ciphertext yet (pre-encrypt sentinel)', async () => {
    const sdk = emptySdk()
    // The sentinel path is only legitimate once the middleware is wired
    // against this SAME sdk — that is what promises a second pass will
    // fill in the ciphertext. Register it the way production does.
    bulkEncryptMiddlewareV3(sdk)
    const codec = codecFor(
      createV3CodecDescriptors(sdk),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const preEncrypt = EncryptedString.from('plaintext')
    expect(await codec.encode(preEncrypt, callCtx)).toBe(preEncrypt)
  })

  it('throws a wiring diagnostic when the sdk has no bulk-encrypt middleware registered', async () => {
    // No `bulkEncryptMiddlewareV3(sdk)` for this sdk: the two-pass write
    // can never complete, so fail at the codec boundary rather than
    // letting the envelope reach the driver as an opaque serialise error.
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    await expect(
      codec.encode(EncryptedString.from('plaintext'), callCtx),
    ).rejects.toThrow(/bulkEncryptMiddlewareV3\(sdk\)/)
  })

  it('does not fire the wiring diagnostic for an already-encrypted envelope', async () => {
    // An envelope carrying ciphertext needs no second pass, so an
    // unregistered sdk is not a misconfig on this path.
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const encrypted = EncryptedString.fromInternal({
      ciphertext: { c: 'abc' },
      table: 'users',
      column: 'email',
      sdk: emptySdk(),
    })
    expect(await codec.encode(encrypted, callCtx)).toBe(
      JSON.stringify({ c: 'abc' }),
    )
  })
})

describe('CipherstashV3CellCodec — decode', () => {
  const routedCtx = (table: string, name: string) =>
    ({ column: { table, name } }) as SqlCodecCallContext

  it('parses JSONB text and constructs the per-castAs envelope with routing context', async () => {
    const sdk = emptySdk()
    const codec = codecFor(
      createV3CodecDescriptors(sdk),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const decoded = await codec.decode(
      '{"c":"abc"}',
      routedCtx('users', 'email'),
    )
    expect(decoded).toBeInstanceOf(EncryptedString)
    const handle = (decoded as EncryptedString).expose()
    expect(handle.ciphertext).toEqual({ c: 'abc' })
    expect(handle.table).toBe('users')
    expect(handle.column).toBe('email')
    expect(handle.sdk).toBe(sdk)
  })

  it('passes driver-pre-parsed objects through without re-parsing', async () => {
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_integer_ord@1',
    )
    const decoded = await codec.decode({ c: 'abc' }, routedCtx('m', 'v'))
    expect(decoded).toBeInstanceOf(EncryptedNumber)
    expect((decoded as EncryptedNumber).expose().ciphertext).toEqual({
      c: 'abc',
    })
  })

  it('constructs EncryptedBigInt for bigint domains and EncryptedJson for the json domain', async () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const bigintDecoded = await codecFor(
      ds,
      'cipherstash/eql-v3/eql_v3_bigint_eq@1',
    ).decode('{"c":"x"}', routedCtx('t', 'c'))
    expect(bigintDecoded).toBeInstanceOf(EncryptedBigInt)
    const jsonDecoded = await codecFor(
      ds,
      'cipherstash/eql-v3/eql_v3_json_search@1',
    ).decode('{"c":"x"}', routedCtx('t', 'c'))
    expect(jsonDecoded).toBeInstanceOf(EncryptedJson)
  })

  it('routes from the payload’s own `i` identifier when no column context exists', async () => {
    // The aggregate / computed-projection case: the SQL runtime resolves
    // no `SqlColumnRef`, but an EQL v3 payload is self-describing. ZeroKMS
    // commits the cell key to `i`, so this is the authoritative source.
    const sdk = emptySdk()
    const codec = codecFor(
      createV3CodecDescriptors(sdk),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const decoded = await codec.decode(
      '{"i":{"t":"users","c":"email"},"c":"abc"}',
      {} as SqlCodecCallContext,
    )
    expect(decoded).toBeInstanceOf(EncryptedString)
    const handle = (decoded as EncryptedString).expose()
    expect(handle.table).toBe('users')
    expect(handle.column).toBe('email')
    expect(handle.sdk).toBe(sdk)
  })

  it('prefers the payload identifier over the query’s column context', async () => {
    // Key commitment makes the payload authoritative: the identifier is
    // what the cell key is bound to, so a value that disagrees with where
    // the query found it must still route by its own identity.
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const decoded = await codec.decode(
      '{"i":{"t":"users","c":"email"},"c":"abc"}',
      routedCtx('other_table', 'other_column'),
    )
    const handle = (decoded as EncryptedString).expose()
    expect(handle.table).toBe('users')
    expect(handle.column).toBe('email')
  })

  it('throws when the payload carries no identifier and there is no column context', async () => {
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    await expect(
      codec.decode('{"c":"abc"}', {} as SqlCodecCallContext),
    ).rejects.toThrow(/routing key/)
  })
})

describe('CipherstashV3CellCodec — JSON plane', () => {
  it('encodeJson renders the per-type opaque marker', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const codec = codecFor(ds, 'cipherstash/eql-v3/eql_v3_integer_ord@1')
    expect(codec.encodeJson(EncryptedNumber.from(1))).toEqual({
      $encryptedNumber: '<opaque>',
    })
  })

  it('decodeJson builds a fully-routed envelope from the payload identifier', () => {
    // The relation-`include()` path: the SQL runtime decodes cells nested
    // in a `json_agg` / `json_build_object` document through `decodeJson`,
    // with no column context. The payload's `i` supplies the routing key
    // and the codec already closes over the SDK, so the envelope is
    // indistinguishable from one built by `decode`.
    const sdk = emptySdk()
    const codec = codecFor(
      createV3CodecDescriptors(sdk),
      'cipherstash/eql-v3/eql_v3_text_eq@1',
    )
    const decoded = codec.decodeJson({
      i: { t: 'users', c: 'email' },
      c: 'abc',
    })
    expect(decoded).toBeInstanceOf(EncryptedString)
    const handle = (decoded as EncryptedString).expose()
    expect(handle.ciphertext).toEqual({
      i: { t: 'users', c: 'email' },
      c: 'abc',
    })
    expect(handle.table).toBe('users')
    expect(handle.column).toBe('email')
    expect(handle.sdk).toBe(sdk)
  })

  it('decodeJson rejects a value carrying no EQL identifier', () => {
    const codec = codecFor(
      createV3CodecDescriptors(emptySdk()),
      'cipherstash/eql-v3/eql_v3_integer_ord@1',
    )
    expect(() => codec.decodeJson({})).toThrow(/identifier/)
    // An `encodeJson` marker is not a round-trip input — the two methods
    // serve different planes.
    expect(() => codec.decodeJson({ $encryptedNumber: '<opaque>' })).toThrow(
      /identifier/,
    )
  })
})
