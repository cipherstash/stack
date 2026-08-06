// End-to-end round-trip on the wasm build path.
//
// Exercises the same encrypt → decrypt cycle the Neon tests cover, but
// goes through `dist/wasm/protect_ffi_inline.js` instead of the
// `@cipherstash/protect-ffi` Neon entry. Auth is delegated to
// `@cipherstash/auth`'s `AccessKeyStrategy` exactly as a real wasm
// consumer would wire it up.
//
// # Prerequisites
//
// 1. Build the wasm artifacts from the repo root: `npm run build:wasm`.
//    Without `dist/wasm/protect_ffi_inline.js` the suite fails fast with
//    a clear error rather than skipping silently.
// 2. Set `CS_WORKSPACE_CRN`, `CS_CLIENT_ACCESS_KEY`, `CS_CLIENT_ID`, and
//    `CS_CLIENT_KEY` (the wasm path takes the dataset client key inline;
//    there's no profile-store fallback).
//
// Missing prerequisites FAIL the suite with a clear error — they never
// skip it. A skipped suite reads as green in CI, which is exactly how a
// misconfigured secret would go unnoticed.

import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

import 'dotenv/config'
import { AccessKeyStrategy } from '@cipherstash/auth/wasm-inline'
import { beforeAll, describe, expect, test } from 'vitest'

const REQUIRED_ENV = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ACCESS_KEY',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
] as const

/**
 * Read the required credentials, throwing (test failure, not a skip) when
 * any are missing. Returning narrowed strings keeps the test bodies free
 * of non-null assertions.
 */
function requireEnv() {
  const missing = REQUIRED_ENV.filter((k) => !process.env[k])
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}. The wasm integration tests need CipherStash credentials — see the header of this file.`,
    )
  }
  return {
    workspaceCrn: process.env.CS_WORKSPACE_CRN as string,
    accessKey: process.env.CS_CLIENT_ACCESS_KEY as string,
    clientId: process.env.CS_CLIENT_ID as string,
    clientKey: process.env.CS_CLIENT_KEY as string,
  }
}

// `__dirname` (CJS) instead of `import.meta.url` because the
// integration-tests tsconfig inherits `module: "node16"` and the package
// has no `"type": "module"`, so .ts files compile as CJS.
const WASM_INLINE_PATH = resolve(
  __dirname,
  '..',
  '..',
  'dist',
  'wasm',
  'protect_ffi_inline.js',
)

/**
 * Import the wasm-inline build, throwing a "run npm run build:wasm" hint
 * (test failure, not a skip) when the artifact is missing — instead of an
 * opaque ESM import error. Dynamic import keeps vitest from trying to
 * resolve the path at module-graph time.
 */
async function loadWasm<T>(): Promise<T> {
  if (!existsSync(WASM_INLINE_PATH)) {
    throw new Error(
      `wasm-inline build not found at ${WASM_INLINE_PATH}. Run \`npm run build:wasm\` from the repo root before running the integration tests.`,
    )
  }
  return (await import(WASM_INLINE_PATH)) as T
}

describe('wasm round-trip', () => {
  type Ciphertext = {
    k: 'ct' | 'sv'
    i: { t: string; c: string }
    c?: string
    hm?: string
  }
  type WasmModule = {
    newClient: (opts: Record<string, unknown>) => Promise<unknown>
    encrypt: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<Ciphertext>
    encryptBulk: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<Ciphertext[]>
    decrypt: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<unknown>
    decryptBulk: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<unknown[]>
    decryptBulkFallible: (
      client: unknown,
      opts: Record<string, unknown>,
    ) => Promise<({ data: unknown } | { error: string })[]>
    isEncrypted: (raw: unknown) => boolean
  }

  let wasm: WasmModule

  beforeAll(async () => {
    // Fail fast on missing prerequisites so every test in the suite
    // reports the same clear error instead of a pile of undefined-env
    // noise further down.
    requireEnv()
    wasm = await loadWasm<WasmModule>()
  })

  test('encrypts and decrypts a scalar value end-to-end', async () => {
    const env = requireEnv()

    // @cipherstash/auth 0.39 takes the full workspace CRN and parses the
    // region from it (earlier versions took only the `<region>.<provider>`
    // segment, requiring callers to split the CRN themselves).
    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            email: {
              // Either vocabulary works now — normalisation moved into the
              // Rust, so this binding accepts the public 'string' spelling
              // too. Canonical is kept here to pin the pass-through path.
              cast_as: 'text',
              indexes: { unique: {} },
            },
          },
        },
      },
      clientOpts: {
        clientId: env.clientId,
        clientKey: env.clientKey,
      },
    })

    const plaintext = 'alice@example.com'
    const ciphertext = await wasm.encrypt(client, {
      plaintext,
      table: 'users',
      column: 'email',
    })

    expect(wasm.isEncrypted(ciphertext)).toBe(true)
    expect(ciphertext.k).toBe('ct')
    expect(ciphertext.i).toEqual({ t: 'users', c: 'email' })
    // unique-index HMAC lives at the top-level `hm` field in EQL v2.3.
    expect(ciphertext.hm).toBeTruthy()
    // MessagePack-Base85 ciphertext lives at top-level `c` for scalar payloads.
    expect(ciphertext.c).toBeTruthy()

    const decrypted = await wasm.decrypt(client, { ciphertext })
    expect(decrypted).toBe(plaintext)
  })

  test('encrypts and decrypts with no authStrategy, via the AutoStrategy arm', async () => {
    // The largest new runtime behaviour in #142, and the only path here that
    // does not hand the Rust a JS strategy object: with `authStrategy` absent,
    // `CredentialOpts::build_strategy()` resolves an `AccessKeyStrategy` from
    // `clientOpts.accessKey` + `workspaceCrn` — `AutoStrategy`'s wasm arm,
    // which is access-key-only because there is no profile store to fall back
    // to. Everything else in this suite goes through `JsAuthStrategy`, so
    // without this case the arm is asserted only at the type level.
    const env = requireEnv()

    const client = await wasm.newClient({
      encryptConfig: {
        v: 1,
        tables: { users: { email: { cast_as: 'text', indexes: {} } } },
      },
      clientOpts: {
        clientId: env.clientId,
        clientKey: env.clientKey,
        workspaceCrn: env.workspaceCrn,
        accessKey: env.accessKey,
      },
    })

    const plaintext = 'auto@example.com'
    const ciphertext = await wasm.encrypt(client, {
      plaintext,
      table: 'users',
      column: 'email',
    })
    expect(wasm.isEncrypted(ciphertext)).toBe(true)
    expect(await wasm.decrypt(client, { ciphertext })).toBe(plaintext)
  })

  test('round-trips a bigint plaintext exactly and rejects out-of-range values', async () => {
    const env = requireEnv()

    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      authStrategy: strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            score: {
              cast_as: 'big_int',
              indexes: { ore: {} },
            },
          },
        },
      },
      clientOpts: {
        clientId: env.clientId,
        clientKey: env.clientKey,
      },
    })

    // i64::MAX — far beyond Number.MAX_SAFE_INTEGER; must survive exactly.
    const plaintext = 9223372036854775807n
    const ciphertext = await wasm.encrypt(client, {
      plaintext,
      table: 'users',
      column: 'score',
    })

    const decrypted = await wasm.decrypt(client, { ciphertext })
    expect(typeof decrypted).toBe('bigint')
    expect(decrypted).toBe(plaintext)

    // 2^63 is just above i64::MAX — the wasm boundary rejects it before
    // serde with a RangeError (the documented class, same as the Neon
    // boundary) naming the bounds and direction.
    const aboveMax = wasm.encrypt(client, {
      plaintext: 2n ** 63n,
      table: 'users',
      column: 'score',
    })
    await expect(aboveMax).rejects.toThrow(
      /above the maximum.*signed 64-bit integer/,
    )
    await expect(aboveMax).rejects.toBeInstanceOf(RangeError)

    // -(2^63) - 1 is just below i64::MIN — the sign detection picks the
    // "below the minimum" wording.
    const belowMin = wasm.encrypt(client, {
      plaintext: -(2n ** 63n) - 1n,
      table: 'users',
      column: 'score',
    })
    await expect(belowMin).rejects.toThrow(
      /below the minimum.*signed 64-bit integer/,
    )
    await expect(belowMin).rejects.toBeInstanceOf(RangeError)
  })

  test('bulk round-trips a mixed bigint / string / number batch', async () => {
    const env = requireEnv()

    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      authStrategy: strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            email: {
              cast_as: 'text',
              indexes: { unique: {} },
            },
            score: {
              cast_as: 'big_int',
              indexes: { ore: {} },
            },
          },
        },
      },
      clientOpts: {
        clientId: env.clientId,
        clientKey: env.clientKey,
      },
    })

    // Mixed batch: exercises the wasm boundary's per-item plaintext
    // rewriting in `encode_plaintext_list` (bigint items get the tagged
    // wire form, the rest are JSON-canonicalized) and the manual JS-array
    // construction in `decrypt_bulk` (needed so bigints decrypt to real JS
    // bigints instead of the serde wire map).
    const plaintexts = [
      { plaintext: 'alice@example.com', table: 'users', column: 'email' },
      { plaintext: 9007199254740993n, table: 'users', column: 'score' },
      { plaintext: 123, table: 'users', column: 'score' },
    ]

    const ciphertexts = await wasm.encryptBulk(client, { plaintexts })
    expect(ciphertexts).toHaveLength(3)

    const decrypted = await wasm.decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })
    // The bigint column ALWAYS decrypts to a JS bigint — including the
    // `123` number input (matches the Neon scalar-bulk suite).
    expect(decrypted).toEqual(['alice@example.com', 9007199254740993n, 123n])

    // decryptBulkFallible: same manual array construction, plus per-item
    // error objects. A corrupted ciphertext yields an `{ error }` arm
    // without poisoning the valid items.
    const fallible = await wasm.decryptBulkFallible(client, {
      ciphertexts: [
        { ciphertext: ciphertexts[1] },
        { ciphertext: { ...ciphertexts[1], c: 'not-a-real-ciphertext' } },
      ],
    })
    expect(fallible).toHaveLength(2)
    expect(fallible[0]).toEqual({ data: 9007199254740993n })
    expect(fallible[1]).toHaveProperty('error')
  })

  test('json plaintexts follow JSON.stringify semantics (Neon parity)', async () => {
    const env = requireEnv()

    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      authStrategy: strategy,
      encryptConfig: {
        v: 1,
        tables: {
          users: {
            profile: {
              cast_as: 'json',
              indexes: {},
            },
          },
        },
      },
      clientOpts: {
        clientId: env.clientId,
        clientKey: env.clientKey,
      },
    })

    // JSON has no bigint: the wasm boundary canonicalizes plaintexts
    // through JSON.stringify, so a bigint nested inside a json-column
    // document rejects with the engine's own TypeError — exactly as it
    // does on Neon, where neon's `Json` extractor stringifies the options
    // object. (Before canonicalization, serde_wasm_bindgen silently folded
    // the bigint into the document as an i64 that decrypted back through
    // f64, rounding above 2^53.)
    await expect(
      wasm.encrypt(client, {
        plaintext: { count: 2n ** 60n + 1n },
        table: 'users',
        column: 'profile',
      }),
    ).rejects.toThrow(TypeError)

    // The rest of JSON.stringify's semantics apply too: `toJSON` is
    // honored (Date → ISO string), `undefined` properties are dropped,
    // and non-finite numbers become `null`.
    const ciphertext = await wasm.encrypt(client, {
      plaintext: {
        joined: new Date('2026-01-02T03:04:05.678Z'),
        nickname: undefined,
        score: Number.NaN,
      },
      table: 'users',
      column: 'profile',
    })
    const decrypted = await wasm.decrypt(client, { ciphertext })
    expect(decrypted).toEqual({
      joined: '2026-01-02T03:04:05.678Z',
      score: null,
    })
  })

  test('rejects unknown keys on the encrypt and decrypt options (#144)', async () => {
    // This is the boundary the `DenyUnknown` marker exists for, and it needs a
    // real client, so it sits here rather than in the credential-free suite
    // below. serde-wasm-bindgen reads a struct by looking up the fields it
    // expects — without the marker every assertion here would pass silently
    // with the key dropped.
    //
    // `lokContext` on a bulk payload is the one that matters: dropped, the
    // value encrypts UNBOUND while the caller believes it is identity-bound,
    // and nothing in the output tells the two apart.
    const env = requireEnv()
    const strategy = AccessKeyStrategy.create(env.workspaceCrn, env.accessKey)

    const client = await wasm.newClient({
      authStrategy: strategy,
      encryptConfig: {
        v: 1,
        tables: { users: { email: { cast_as: 'text', indexes: {} } } },
      },
      clientOpts: { clientId: env.clientId, clientKey: env.clientKey },
    })

    await expect(
      wasm.encrypt(client, {
        plaintext: 'alice@example.com',
        table: 'users',
        column: 'email',
        unverifedContext: { sub: 'user-1' },
      }),
    ).rejects.toThrow(/unknown field `unverifedContext`/)

    await expect(
      wasm.encryptBulk(client, {
        plaintexts: [
          {
            plaintext: 'alice@example.com',
            table: 'users',
            column: 'email',
            lokContext: { identityClaim: ['sub'] },
          },
        ],
      }),
    ).rejects.toThrow(/unknown field `lokContext`/)

    const ciphertext = await wasm.encrypt(client, {
      plaintext: 'alice@example.com',
      table: 'users',
      column: 'email',
    })
    await expect(
      wasm.decrypt(client, { ciphertext, lockContexts: { identityClaim: [] } }),
    ).rejects.toThrow(/unknown field `lockContexts`/)
  })
})

// `newClient` validation that needs no credentials and no network. Since the
// options were unified with the Neon entry, an absent `authStrategy` is NOT an
// error — it falls through to `CredentialOpts::build_strategy()`, which on
// wasm resolves an `AccessKeyStrategy` (the target's `AutoStrategy` arm, with
// the profile-store fallback compiled out). So the interesting cases are what
// happens when nothing resolves, and when a supplied strategy is malformed.
describe('wasm newClient validation', () => {
  type WasmModule = {
    newClient: (opts: Record<string, unknown>) => Promise<unknown>
  }
  const minimalConfig = { v: 1, tables: {} }

  test('rejects when neither a strategy nor credentials resolve', async () => {
    // No authStrategy and no clientOpts: build_strategy() finds nothing, and
    // wasm has no env or profile store to fall back to. `std::env::var` is
    // always `Err` on wasm32-unknown-unknown, so even a populated environment
    // cannot rescue this — credentials must be passed explicitly.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({ encryptConfig: minimalConfig }),
    ).rejects.toThrow(/Not authenticated/)
  })

  test('rejects when a strategy resolves but the client key is missing', async () => {
    // The key provider is separate from auth: a valid strategy still needs
    // clientId + clientKey, because there is no profile store to fall back to.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        authStrategy: { getToken: async () => ({ token: 'unused' }) },
        encryptConfig: minimalConfig,
      }),
    ).rejects.toThrow(
      /clientOpts\.clientId and clientOpts\.clientKey are required/,
    )
  })

  test('rejects a non-callable getToken', async () => {
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        authStrategy: { getToken: 42 },
        encryptConfig: minimalConfig,
      }),
    ).rejects.toThrow(/opts\.authStrategy\.getToken is not a function/)
  })

  test('rejects a non-object authStrategy without blaming getToken', async () => {
    // `Reflect::get` throws on a non-object receiver, so without a guard this
    // surfaced as "opts.authStrategy.getToken not found: TypeError: Reflect.get
    // called on non-object", plus a stack trace — pointing at the wrong thing.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({ authStrategy: 'oops', encryptConfig: minimalConfig }),
    ).rejects.toThrow(
      /opts\.authStrategy must be an object with a getToken\(\) method/,
    )
  })

  test('names the deprecated key when that is the one the caller used', async () => {
    // Telling someone still on `strategy` to go look at `opts.authStrategy`
    // sends them to a property they never wrote.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        strategy: { getToken: 42 },
        encryptConfig: minimalConfig,
      }),
    ).rejects.toThrow(/opts\.strategy\.getToken is not a function/)
  })

  // Unknown keys (#144). This boundary is where it matters: serde-wasm-bindgen
  // reads a struct by looking up the fields it expects, so an undeclared key is
  // invisible to it and `deny_unknown_fields` alone rejects nothing. The
  // `DenyUnknown` marker in `crates/protect-ffi/src/lib.rs` is what puts these
  // objects on the path that enumerates them. The Neon half is
  // `strict-options.test.ts`.
  test('rejects credentials passed at the top level', async () => {
    // Exactly how #144 was found: four integration tests in #143 failed with
    // "clientOpts.clientId and clientOpts.clientKey are required" while
    // passing both, because the credentials had moved under `clientOpts` and
    // the old top-level spelling was being dropped in silence.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        encryptConfig: minimalConfig,
        clientId: '8f7ae6de-6b6a-4f9e-9dd4-2b2e39bc3b52',
        clientKey: 'ab',
      }),
    ).rejects.toThrow(/unknown field `clientId`/)
  })

  test('rejects an unknown key inside clientOpts', async () => {
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        encryptConfig: minimalConfig,
        clientOpts: { region: 'ap-southeast-2' },
      }),
    ).rejects.toThrow(/unknown field `region`/)
  })

  // Neither case above needs `DenyUnknown`: `ClientOpts` reaches the map path
  // through its own flattened credentials. `eqlVersion` is a `NewClientOptions`
  // field, and that struct carries the marker for exactly this — without it
  // serde would look up the fields it expects, never see the typo, and build a
  // client with the default wire version.
  test('rejects an unknown key that only the marker can catch', async () => {
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({ encryptConfig: minimalConfig, eqlVerison: 3 }),
    ).rejects.toThrow(/unknown field `eqlVerison`/)
  })

  test('reports a throwing getter instead of unwinding out of wasm', async () => {
    // The strip copies the options with `Object.assign`, which reads every own
    // enumerable property — so a getter among them runs inside the copy. js-sys
    // declares `assign` without `catch`, and that throw would travel straight
    // through the wasm frames, skipping the destructors of the zeroizing values
    // this call goes on to build. `try_assign` makes it an ordinary rejection.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        get encryptConfig(): unknown {
          throw new Error('getter boom')
        },
      }),
    ).rejects.toThrow(/opts could not be copied/)
  })

  test('still accepts the deprecated `strategy` name', async () => {
    // Both auth keys are lifted off the object with `Reflect` and stripped
    // before serde, since a struct that denies unknown fields would otherwise
    // reject them. Reaching the credential error proves the whole round trip:
    // the key was accepted, used as the strategy, and removed.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient({
        strategy: { getToken: async () => ({ token: 'unused' }) },
        encryptConfig: minimalConfig,
      }),
    ).rejects.toThrow(
      /clientOpts\.clientId and clientOpts\.clientKey are required/,
    )
  })

  test('strips the auth strategy from a copy, not the caller object', async () => {
    // A config reused across calls would otherwise lose its strategy on the
    // second one.
    const wasm = await loadWasm<WasmModule>()
    const opts = {
      authStrategy: { getToken: async () => ({ token: 'unused' }) },
      encryptConfig: minimalConfig,
    }
    await expect(wasm.newClient(opts)).rejects.toThrow(
      /clientOpts\.clientId and clientOpts\.clientKey are required/,
    )
    expect('authStrategy' in opts).toBe(true)
  })

  // The two cases where the caller's property descriptors could plausibly
  // defeat the strip. Reaching the credential error means deserialization
  // succeeded, which means the key was gone by the time serde ran.
  test('strips it from a frozen options object', async () => {
    // The delete lands on the copy, and `Object.assign` writes plain
    // configurable properties onto a fresh object — the caller's descriptors
    // don't carry over to constrain it.
    const wasm = await loadWasm<WasmModule>()
    await expect(
      wasm.newClient(
        Object.freeze({
          authStrategy: { getToken: async () => ({ token: 'unused' }) },
          encryptConfig: minimalConfig,
        }),
      ),
    ).rejects.toThrow(
      /clientOpts\.clientId and clientOpts\.clientKey are required/,
    )
  })

  test('still finds a non-enumerable auth strategy', async () => {
    // `Object.assign` copies own ENUMERABLE properties, so this one never
    // reaches the copy and there is nothing to strip. It is read off the
    // original beforehand, so it is still used rather than lost.
    const wasm = await loadWasm<WasmModule>()
    const opts: Record<string, unknown> = { encryptConfig: minimalConfig }
    Object.defineProperty(opts, 'authStrategy', {
      value: { getToken: async () => ({ token: 'unused' }) },
      enumerable: false,
    })
    await expect(wasm.newClient(opts)).rejects.toThrow(
      /clientOpts\.clientId and clientOpts\.clientKey are required/,
    )
  })
})
