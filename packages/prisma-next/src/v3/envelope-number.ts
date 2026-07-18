/**
 * `EncryptedNumber` envelope — the user-facing input/output type for the
 * v3 number-family codecs (`cipherstash/eql-v3/eql_v3_integer*@1`,
 * `..._smallint*`, `..._numeric*`, `..._real*`, `..._double*`). Concrete
 * subclass of {@link EncryptedEnvelopeBase} parameterised on `number`.
 *
 * A SIBLING of the v2 `EncryptedDouble` — NOT a subclass or alias. Its
 * distinct `typeName` drives the `$encryptedNumber` placeholder marker;
 * keeping the class separate prevents `value instanceof EncryptedNumber`
 * from matching a v2 `EncryptedDouble` (a cross-version leak). Every v3
 * number-castAs domain (integer / smallint / numeric / real / double)
 * renders as `EncryptedNumber`.
 *
 * No `parseDecryptedValue` override is needed: the SDK's polymorphic
 * `bulkDecrypt` / single-cell `decrypt` already returns numeric
 * plaintexts as `number`; the base's default identity cast suffices.
 */

import {
  EncryptedEnvelopeBase,
  type EncryptedEnvelopeFromInternalArgs,
  type EncryptedEnvelopeHandle,
} from '../execution/envelope-base'

export type EncryptedNumberHandle = EncryptedEnvelopeHandle<number>

export type EncryptedNumberFromInternalArgs = EncryptedEnvelopeFromInternalArgs

export class EncryptedNumber extends EncryptedEnvelopeBase<number> {
  protected override get typeName(): string {
    return 'EncryptedNumber'
  }

  /**
   * Construct a write-side envelope from a plaintext number. Bulk-encrypt
   * middleware populates the handle's ciphertext slot before the codec
   * encodes the envelope to wire format.
   */
  static from(plaintext: number): EncryptedNumber {
    return new EncryptedNumber({
      plaintext,
      ciphertext: undefined,
      table: undefined,
      column: undefined,
      sdk: undefined,
    })
  }

  /**
   * Construct a read-side envelope from a wire ciphertext + the column
   * identity + the SDK used to decrypt the cell. Called from the codec
   * `decode` body.
   */
  static fromInternal(args: EncryptedNumberFromInternalArgs): EncryptedNumber {
    return new EncryptedNumber({
      plaintext: undefined,
      ciphertext: args.ciphertext,
      table: args.table,
      column: args.column,
      sdk: args.sdk,
    })
  }
}
