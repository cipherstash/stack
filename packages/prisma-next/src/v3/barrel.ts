/**
 * v3 user-facing value types, surfaced through the v3 subtree.
 * Re-exports the version-neutral envelope classes (including
 * `EncryptedJson` — the json domain is a first-class v3 domain) plus the
 * v3-only `EncryptedNumber`. Pulls in NO v2 wire/codec code.
 */
export { EncryptedBigInt } from '../execution/envelope-bigint'
export { EncryptedBoolean } from '../execution/envelope-boolean'
export { EncryptedDate } from '../execution/envelope-date'
export { EncryptedJson } from '../execution/envelope-json'
export { EncryptedString } from '../execution/envelope-string'
export { EncryptedNumber } from './envelope-number'
