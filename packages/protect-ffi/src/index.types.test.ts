import { describe, expect, it } from 'vitest'
import type {
  AuthStrategy,
  DecryptResult,
  EncryptedV3Query,
  EncryptQueryOptions,
  Indexes,
  IndexTypeName,
  QueryPayload,
  TextSearchOreQuery,
  TextSearchQuery,
  TokenResultEnvelope,
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

  it('accepts the remedy fields an AuthFailure carries', () => {
    // Both seams read `help` and `url` off the failure object — see
    // `AuthDiagnosticRelay` in crates/protect-ffi/src/lib.rs — so a strategy
    // written in TypeScript has to be able to supply them. `@cipherstash/auth`
    // declares both on every member of its `AuthFailure` union.
    //
    // Typed as the envelope rather than through `AuthStrategy`: a union return
    // type relaxes excess-property checking, so the same literal inside a
    // `getToken` passes whether or not the fields are declared, and the test
    // would pin nothing.
    const failure: TokenResultEnvelope = {
      failure: {
        type: 'USAGE_LIMIT_EXCEEDED',
        error: new Error('Insufficient balance. Please upgrade your plan.'),
        help: 'Upgrade the plan at https://dashboard.cipherstash.com',
        url: 'https://dashboard.cipherstash.com',
      },
    }
    const strategy: AuthStrategy = { getToken: async () => failure }

    expect(typeof strategy.getToken).toBe('function')
  })
})

// The failure arm of a per-item `decryptBulkFallible` result is built from the
// same Rust `Diagnostic` as a thrown error (`DecryptResult::from_error`), so it
// carries the same fields. A field the Rust can set and the type does not name
// is a value a caller cannot read without an assertion.
describe('DecryptResult', () => {
  it('names every field the Rust failure arm can set', () => {
    const failure: DecryptResult = {
      error: 'Insufficient balance. Please upgrade your plan.',
      code: 'UNKNOWN',
      authCode: 'USAGE_LIMIT_EXCEEDED',
      help: 'Upgrade the plan at https://dashboard.cipherstash.com',
      url: 'https://dashboard.cipherstash.com',
    }

    expect(failure).toBeDefined()
  })

  it('keeps every diagnostic field optional', () => {
    // Absent, not null: both bindings omit a field the error has no value for,
    // so `error` alone must remain a complete failure item.
    const failure: DecryptResult = { error: 'invalid ciphertext' }

    expect(failure).toBeDefined()
  })
})
