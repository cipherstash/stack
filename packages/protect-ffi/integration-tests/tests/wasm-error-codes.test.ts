// Error codes on the wasm build.
//
// The Neon entry has had coded errors all along; this build had none. The code
// was reconstructed in `src/index.cts` by matching the message, and wasm has no
// such wrapper — wasm-bindgen generates its own glue — so every error it threw
// arrived bare. Rust attaches `err.code` at both boundaries now (#146), and
// this proves it on the entry that had nothing.
//
// # Prerequisites
//
// Only the wasm build (`npm run build:wasm`). Deliberately no credentials:
// every case below is config validation, which fails before any network I/O.
// That is what lets these run anywhere, unlike `wasm-round-trip.test.ts` — and
// the coverage gap that suite represents is #149.

import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

import { describe, expect, test } from 'vitest'

// `__dirname` (CJS) instead of `import.meta.url` because the integration-tests
// tsconfig inherits `module: "node16"` and the package has no `"type":
// "module"`, so .ts files compile as CJS.
const WASM_INLINE_PATH = resolve(
  __dirname,
  '..',
  '..',
  'dist',
  'wasm',
  'protect_ffi_inline.js',
)

type WasmModule = {
  PROTECT_ERROR_CODES: readonly string[]
  isProtectErrorCode: (value: unknown) => boolean
  newClient: (opts: unknown) => Promise<unknown>
}

async function loadWasm(): Promise<WasmModule> {
  if (!existsSync(WASM_INLINE_PATH)) {
    throw new Error(
      `wasm-inline build not found at ${WASM_INLINE_PATH}. Run \`npm run build:wasm\` from the repo root before running the integration tests.`,
    )
  }
  return (await import(WASM_INLINE_PATH)) as WasmModule
}

/** The error `newClient` threw, or a failure if it did not throw. */
async function newClientError(opts: unknown): Promise<{
  code?: unknown
  message: string
}> {
  const { newClient } = await loadWasm()
  try {
    await newClient(opts)
  } catch (err) {
    const { code, message } = err as { code?: unknown; message?: unknown }
    return { code, message: String(message) }
  }
  throw new Error('expected newClient to throw')
}

describe('wasm error codes', () => {
  test('exports the runtime error helpers', async () => {
    const { PROTECT_ERROR_CODES, isProtectErrorCode } = await loadWasm()

    expect(PROTECT_ERROR_CODES).toContain('UNSUPPORTED_CONFIG_VERSION')
    expect(isProtectErrorCode('UNSUPPORTED_CONFIG_VERSION')).toBe(true)
    expect(isProtectErrorCode('ECONNRESET')).toBe(false)
  })

  test('a match index on a non-text column', async () => {
    const err = await newClientError({
      encryptConfig: {
        v: 1,
        tables: { users: { age: { cast_as: 'int', indexes: { match: {} } } } },
      },
    })

    expect(err.code).toBe('MATCH_REQUIRES_TEXT')
  })

  test('a ste_vec index on a non-JSON column', async () => {
    const err = await newClientError({
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            meta: {
              cast_as: 'text',
              indexes: { ste_vec: { prefix: 'users/meta' } },
            },
          },
        },
      },
    })

    expect(err.code).toBe('STE_VEC_REQUIRES_JSON_CAST_AS')
  })

  test('a config version this build does not support', async () => {
    const err = await newClientError({
      encryptConfig: {
        v: 2,
        tables: {
          users: { email: { cast_as: 'text', indexes: { unique: {} } } },
        },
      },
    })

    expect(err.code).toBe('UNSUPPORTED_CONFIG_VERSION')
  })

  test('an eqlVersion outside the supported range', async () => {
    // Unlike the three above, this one is raised by this crate rather than by
    // cipherstash-config — both paths have to carry a code, and only this kind
    // did before the `into_config_map` call was routed through `Error`.
    const err = await newClientError({
      encryptConfig: {
        v: 1,
        tables: {
          users: { email: { cast_as: 'text', indexes: { unique: {} } } },
        },
      },
      eqlVersion: 4,
    })

    expect(err.code).toBe('INVALID_EQL_VERSION')
  })

  test('the code is additional to the message, not a replacement', async () => {
    const err = await newClientError({
      encryptConfig: {
        v: 2,
        tables: {
          users: { email: { cast_as: 'text', indexes: { unique: {} } } },
        },
      },
    })

    expect(err.message).toContain('unsupported config version: 2')
  })

  test('a boundary failure with no Error variant carries no code', async () => {
    // An unknown key is rejected by serde before any `Error` exists, so there
    // is no variant to take a code from. Claiming one would be inventing it —
    // which is the habit #146 removed.
    const err = await newClientError({
      encryptConfig: {
        v: 1,
        tables: {
          users: { email: { cast_as: 'text', indexes: { unique: {} } } },
        },
      },
      nope: 1,
    })

    expect(err.code).toBeUndefined()
    expect(err.message).toContain('unknown field `nope`')
  })
})
