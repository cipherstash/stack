import type { CipherstashSdk } from '../../../src/execution/sdk'

// A v3-aware fake SDK shared by the v3 codec / middleware / decrypt tests.
// `bulkEncryptQuery` joins the real `CipherstashSdk` interface in Task 10; until
// then it is an extra method here, so the literal is cast to `CipherstashSdk`.
export type FakeCipherstashSdk = CipherstashSdk & {
  bulkEncryptQuery(args: {
    routingKey: { table: string; column: string }
    queryType: string
    values: ReadonlyArray<unknown>
    signal?: AbortSignal
  }): Promise<ReadonlyArray<unknown>>
}

export function makeFakeSdk(overrides: Partial<FakeCipherstashSdk> = {}): FakeCipherstashSdk {
  return {
    decrypt: async () => 'plaintext',
    // full stored payload (has ciphertext `c`)
    bulkEncrypt: async ({ values }) => values.map((_v, i) => ({ v: 2, i: { t: 't', c: 'c' }, c: `ct-${i}` })),
    bulkDecrypt: async ({ ciphertexts }) => ciphertexts.map(() => 'plaintext'),
    // search term (index-only, NO ciphertext `c`)
    bulkEncryptQuery: async ({ values }) => values.map((_v, i) => ({ v: 2, i: { t: 't', c: 'c' }, hm: `hm-${i}` })),
    ...overrides,
  } as FakeCipherstashSdk
}
