import { describe, expect, it, vi } from 'vitest'

// This unit test only covers `getColumnName`, which resolves a column's name
// structurally and never touches WASM. Mock the `/wasm-inline` specifiers so
// Vitest can load `../src/wasm-inline` without resolving the real inlined WASM
// entries (which aren't exported for the test bundler).
vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    create: vi.fn(),
  },
}))

vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ({
  decrypt: vi.fn(),
  encrypt: vi.fn(),
  isEncrypted: vi.fn(),
  newClient: vi.fn(),
}))

import { encryptedColumn, encryptedField } from '../src/schema'
import { encryptedTextSearchColumn } from '../src/schema/v3'
import { getColumnName } from '../src/wasm-inline'

describe('wasm-inline getColumnName', () => {
  it('returns the name for a v2 EncryptedColumn', () => {
    expect(getColumnName(encryptedColumn('email'))).toBe('email')
  })

  it('returns the name for a v2 EncryptedField', () => {
    expect(getColumnName(encryptedField('profile'))).toBe('profile')
  })

  it('returns the name for a v3 EncryptedTextSearchColumn (structural, no instanceof)', () => {
    // Regression: widening EncryptOptions.column to the structural
    // BuildableColumn made v3 columns type-check at the wasm-inline encrypt
    // entry, but the old `instanceof EncryptedColumn || EncryptedField` gate
    // threw at runtime. The entry now resolves the name structurally so a v3
    // column genuinely round-trips through WasmEncryptionClient.encrypt().
    expect(getColumnName(encryptedTextSearchColumn('email'))).toBe('email')
  })

  it('throws when given a value that does not expose getName()', () => {
    // Plain JS callers can bypass the type system — guard at runtime.
    expect(() => getColumnName({} as never)).toThrow(/getName/)
  })
})
