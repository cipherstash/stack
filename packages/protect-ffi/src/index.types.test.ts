import { describe, expect, it } from 'vitest'
import type {
  AuthStrategy,
  EncryptQueryOptions,
  EncryptedV3Query,
  IndexTypeName,
  Indexes,
  QueryPayload,
  TextSearchOreQuery,
  TextSearchQuery,
} from './index.cjs'

// Every index that can be configured via `Indexes` must also be targetable
// from `encryptQuery` / `encryptQueryBulk` via `IndexTypeName`. The native
// side accepts all of these (see find_index_for_type in
// crates/protect-ffi/src/lib.rs).
type ConfigurableIndexName = keyof Indexes

describe('IndexTypeName', () => {
  it('covers every configurable index, including ope', () => {
    // Type-level assertion: the two unions must be identical. If a name is
    // added to `Indexes` without being queryable (or vice versa), this fails
    // to typecheck (enforced by `npm run test:typecheck`).
    const configurableIsQueryable: IndexTypeName =
      null as unknown as ConfigurableIndexName
    const queryableIsConfigurable: ConfigurableIndexName =
      null as unknown as IndexTypeName

    const names: IndexTypeName[] = ['ste_vec', 'match', 'ore', 'ope', 'unique']
    expect(names).toContain('ope')
    expect(configurableIsQueryable).toBeNull()
    expect(queryableIsConfigurable).toBeNull()
  })

  it('allows encryptQuery / encryptQueryBulk opts to target an ope index', () => {
    const opts: EncryptQueryOptions = {
      plaintext: 42,
      column: 'salary',
      table: 'employees',
      indexType: 'ope',
    }
    const payload: QueryPayload = {
      plaintext: 42,
      column: 'salary',
      table: 'employees',
      indexType: 'ope',
    }
    expect(opts.indexType).toBe('ope')
    expect(payload.indexType).toBe('ope')
  })
})

describe('EncryptedV3Query', () => {
  it('spans scalar operands, the containment needle, and bare selectors', () => {
    // Type-level assertions: each v3 encryptQuery output shape must be
    // assignable to the union (enforced by `npm run test:typecheck`).
    // The bare search domain orders by the CLLW-OPE `op` term; its ORE twin
    // (`ob`) is the separate text_search_ore domain. Both are operands.
    const scalar: EncryptedV3Query = {
      v: 3,
      i: { t: 'users', c: 'email' },
      hm: 'aa',
      op: 'bb',
      bf: [1, 2],
    } satisfies TextSearchQuery
    const scalarOre: EncryptedV3Query = {
      v: 3,
      i: { t: 'users', c: 'email' },
      hm: 'aa',
      ob: ['bb'],
      bf: [1, 2],
    } satisfies TextSearchOreQuery
    const needle: EncryptedV3Query = { sv: [{ s: 'aa' }] }
    const selector: EncryptedV3Query = 'deadbeef'

    // Scalar operands are term-only: `c` must not typecheck.
    const withCiphertext: TextSearchQuery = {
      v: 3,
      i: { t: 'users', c: 'email' },
      hm: 'aa',
      op: 'bb',
      bf: [1, 2],
      // @ts-expect-error — a query operand carries no ciphertext
      c: 'nope',
    }

    expect(scalar).toBeDefined()
    expect(scalarOre).toBeDefined()
    expect(needle).toBeDefined()
    expect(selector).toBe('deadbeef')
    expect(withCiphertext).toBeDefined()
  })
})

// `AuthStrategy` must describe the contract the native and WASM clients
// actually implement. Since 0.28.0 both accept either a bare `{ token }` or a
// `@byteslice/result` envelope; `@cipherstash/auth` >= 0.41 returns the latter.
// Declaring only the bare payload made real auth strategies unassignable.
describe('AuthStrategy', () => {
  it('accepts the bare { token } payload (auth <= 0.40, custom strategies)', () => {
    const strategy: AuthStrategy = {
      getToken: async () => ({ token: 'service-token' }),
    }

    expect(typeof strategy.getToken).toBe('function')
  })

  it('accepts the Result envelope returned by @cipherstash/auth >= 0.41', () => {
    const success: AuthStrategy = {
      getToken: async () => ({ data: { token: 'service-token' } }),
    }
    const failure: AuthStrategy = {
      getToken: async () => ({
        failure: { type: 'NOT_AUTHENTICATED', error: new Error('nope') },
      }),
    }

    expect(typeof success.getToken).toBe('function')
    expect(typeof failure.getToken).toBe('function')
  })
})
