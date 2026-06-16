/**
 * EQL v3 cell codec for the `cipherstash/string-v3@1` codec id.
 *
 * Reuses the shared {@link makeCipherstashCellCodec} body (encode/decode,
 * two-pass write path, middleware-misconfig diagnostic) but overrides the
 * wire-format codec and DB metadata for v3:
 *
 *   - **Wire:** plain jsonb (`encodeEqlV3Wire` / `decodeEqlV3Wire`), NOT the v2
 *     `eql_v2_encrypted` composite literal — v3 columns are `CREATE DOMAIN … AS
 *     jsonb`.
 *   - **Metadata:** its own `targetTypes` (the four `eql_v3.text*` domains) and
 *     base `nativeType` (`eql_v3.text`). The per-column index domain
 *     (`text_eq`/`text_match`/`text_ord`) is emitted by the migration hook's
 *     `expandNativeType` (codec-hooks-v3.ts), not here.
 *   - **Misconfig diagnostic:** names `bulkEncryptV3Middleware` (the v3 write
 *     middleware registers against the same sdk-keyed WeakSet as v2).
 *
 * v3 reuses the {@link EncryptedString} envelope (a stored v3 payload `{v,i,c}`
 * is decrypt-compatible with the v2 read path — see decrypt-all-v3.test.ts).
 */

import { CIPHERSTASH_STRING_V3_CODEC_ID } from '../extension-metadata/constants'
import { encodeEqlV3Wire } from '../v3/wire-codec'
import { decodeEqlV3Wire } from '../v3/wire-codec'
import { type CipherstashCellCodec, makeCipherstashCellCodec } from './cell-codec-factory'
import { EncryptedString } from './envelope-string'
import type { CipherstashSdk } from './sdk'

const V3_TARGET_TYPES = ['eql_v3.text', 'eql_v3.text_eq', 'eql_v3.text_match', 'eql_v3.text_ord'] as const

export function createCipherstashStringV3Codec(sdk: CipherstashSdk): CipherstashCellCodec<EncryptedString> {
  return makeCipherstashCellCodec(sdk, {
    codecId: CIPHERSTASH_STRING_V3_CODEC_ID,
    typeName: 'EncryptedString',
    fromInternal: EncryptedString.fromInternal,
    encodeWire: encodeEqlV3Wire,
    decodeWire: decodeEqlV3Wire,
    targetTypes: V3_TARGET_TYPES,
    nativeType: 'eql_v3.text',
    middlewareName: 'bulkEncryptV3Middleware',
  })
}
