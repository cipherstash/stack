import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { PlaintextInput } from '@/types'

/**
 * Hand a plaintext to the FFI. This is where the typed encrypt operations
 * (`encrypt`, `bulkEncrypt`, `encryptQuery`) assert a plaintext type. The model
 * paths in `./model-helpers` (`encryptModelFields` / `bulkEncryptModels` and
 * their lock-context variants) do NOT route through here: they walk a model as
 * `Record<string, unknown>` and still assert each field with their own
 * `value as string` cast. It exists because the FFI's declared input union,
 * `JsPlaintext`, is narrower than what the FFI actually accepts:
 *
 * - `Date` — not in `JsPlaintext`; serialized via `toJSON` at the boundary.
 * - a `types.Json` document whose arrays hold `null` elements —
 *   `JsPlaintext[]` omits `null`, but the document is serialized as JSON and
 *   the FFI takes it.
 *
 * (`bigint` IS in `JsPlaintext`; a top-level `null` is excluded by the
 * signature, because every caller short-circuits `null` before encrypting.)
 *
 * Delete this, and call the FFI with the value directly, once `JsPlaintext`
 * admits both.
 */
export function toJsPlaintext(value: NonNullable<PlaintextInput>): JsPlaintext {
  return value as JsPlaintext
}
