// A stand-in for the wasm `OidcFederationStrategy`, shared by the adapter
// suites (`next.test.ts`, `start.test.ts`). It lets them exercise an adapter's
// OWN wiring — where the cookie is read and written, how the token is handed
// on — deterministically and offline; the real federate-or-reuse + cookie
// round-trip against a CTS server is `oidc-cookie-roundtrip.test.ts`.
//
// Install it in a test file with
//
//   vi.mock('../wasm-inline.mjs', async () =>
//     (await import('./helpers/fake-federation')).wasmInlineMock(),
//   )
//
// The dynamic import matters: `vi.mock` is hoisted above the file's imports,
// so its factory cannot close over a statically imported binding. The mocks
// below are module singletons, so the factory and the test file see the same
// `create` / `getToken` / `free`.

import { vi } from 'vitest'
import { WORKSPACE_ID } from './test-fixtures'

export { WORKSPACE_ID }
export const WORKSPACE_CRN = `crn:ap-southeast-2.aws:${WORKSPACE_ID}`

/** What the adapter hands the strategy as its `store`. */
export type FakeStore = {
  load(): Promise<string | null>
  save(json: string): Promise<void>
}
type CreateOptions = { store?: FakeStore; baseUrl?: string }

export const create = vi.fn()
export const getToken = vi.fn()
export const free = vi.fn()

/** The module `../wasm-inline.mjs` is replaced with. */
export function wasmInlineMock() {
  return {
    OidcFederationStrategy: {
      create: (crn: string, getJwt: () => unknown, options: CreateOptions) =>
        create(crn, getJwt, options),
    },
  }
}

/** The `TokenResult` a successful federation resolves to. */
export function tokenResult(overrides: Record<string, unknown> = {}) {
  return {
    token: 'header.payload.signature',
    subject: `CS|${WORKSPACE_ID}`,
    workspaceId: WORKSPACE_ID,
    issuer: 'https://cts.example.com',
    services: { zerokms: 'https://zerokms.example.com' },
    ...overrides,
  }
}

/** The token JSON the fake strategy persists through the store. */
export function storedTokenJson(): string {
  return JSON.stringify({
    access_token: 'header.payload.signature',
    expires_at: Math.floor(Date.now() / 1000) + 3600,
  })
}

/**
 * Reset the mocks and install the default fake strategy: `getToken()` writes
 * the token to the store (so the cookie path is exercised) and resolves a
 * Result-wrapped `TokenResult`. Both `create()` and `getToken()` return
 * `@byteslice/result` Results (`{ data }` on success), matching the real wasm
 * surface the adapters unwrap. Call from `beforeEach`.
 */
export function installFakeStrategy(): void {
  getToken.mockReset()
  free.mockReset()
  create.mockReset()
  create.mockImplementation(
    (_crn: string, _getJwt: () => unknown, options: CreateOptions) => {
      getToken.mockImplementation(async () => {
        await options.store?.save(storedTokenJson())
        return { data: tokenResult() }
      })
      return { data: { getToken, free } }
    },
  )
}

/** Make the next federation fail with `message`, as a `{ failure }` Result. */
export function failFederation(message = 'federation failed'): void {
  create.mockImplementation(() => {
    getToken.mockResolvedValue({
      failure: { type: 'SERVER_ERROR', error: new Error(message) },
    })
    return { data: { getToken, free } }
  })
}
