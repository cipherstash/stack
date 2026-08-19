import type { WasmEncryptionClient } from '@cipherstash/stack/wasm-inline'
import type { EncryptionFactory } from './create'

/**
 * Make a `WasmEncryptionClient` speak the protocol this adapter's query
 * pipeline consumes (#708 review, P1).
 *
 * The two engines are NOT drop-in for each other, and the differences are all
 * silent at construction — which is exactly why the edge entry needs this
 * rather than a cast. Three of them matter here:
 *
 * 1. **`decryptModel` / `bulkDecryptModels` require the table.** The WASM
 *    client resolves date fields from a per-table map and throws without one;
 *    the native client derives the table from the payloads instead. The call
 *    sites in `query-results.ts` now pass `ctx.table` for both, which the
 *    native client simply ignores — so one call shape serves both engines.
 * 2. **Operations are plain Results, not chainable operations.** The native
 *    client returns a thenable carrying `.withLockContext()` and `.audit()`;
 *    the WASM one returns `Promise<Result>`. `withOpContext` only reaches for
 *    those methods when a lock context or audit config is set, so the common
 *    path is unaffected — but reaching for a method that is not there would be
 *    a bare `TypeError` naming an internal, from a caller's perspective
 *    unrelated to what they did. Both are attached here and throw a sentence
 *    that names the gap instead.
 * 3. **`bulkEncrypt` has a different signature**, and it is optional on the
 *    consumed protocol — `query-encrypt.ts` falls back to per-term `encrypt`
 *    when it is absent. It is deliberately NOT forwarded: the fallback is a
 *    supported, already-exercised path, whereas forwarding a mismatched
 *    signature would fail at the FFI boundary. The cost is one ZeroKMS round
 *    trip per distinct filter value rather than one per query, which is worth
 *    revisiting, but not by guessing at the shape.
 *
 * Lock context is a genuine capability gap on the WASM entry (cipherstash/stack#797),
 * not a plumbing oversight here: values written through it carry no identity
 * condition on key retrieval. Failing loudly is the only honest option —
 * silently dropping the claim would produce data that any keyset holder can
 * decrypt, which is precisely what the caller asked not to happen.
 */

/** The message both unsupported chainers raise. */
function unsupported(method: string): Error {
  return new Error(
    `[supabase v3]: \`${method}()\` is not available on the edge entry (\`@cipherstash/stack-supabase/wasm-inline\`) — the WASM engine does not implement it (cipherstash/stack#797). ` +
      (method === 'withLockContext'
        ? 'Identity-bound encryption needs the native entry on Node. Dropping the claim silently would write values any keyset holder could decrypt, so this fails instead.'
        : 'Run the operation on the native entry if you need it.'),
  )
}

/**
 * Attach the chainers the pipeline may reach for, so a caller who used one
 * gets a sentence rather than `op.withLockContext is not a function`.
 *
 * Mutating the promise is deliberate: the pipeline awaits the same object it
 * decorates, so a wrapper object would have to re-implement `then` to stay
 * awaitable, and the two could drift.
 */
function withUnsupportedChainers<R>(promise: Promise<R>): Promise<R> {
  return Object.assign(promise, {
    withLockContext(): never {
      throw unsupported('withLockContext')
    },
    audit(): never {
      throw unsupported('audit')
    },
  })
}

/**
 * Wrap `Encryption` from `@cipherstash/stack/wasm-inline` into the factory the
 * shared `construct` consumes.
 *
 * Only the methods the pipeline actually calls are forwarded — `encrypt`,
 * `encryptModel`, `bulkEncryptModels`, `decryptModel`, `bulkDecryptModels`.
 * Anything else is absent on purpose: an unforwarded method is a loud
 * `undefined is not a function` at the one call site that wanted it, which is
 * a better failure than a forwarded method whose signature does not match.
 */
export function adaptWasmEncryption(
  createWasmClient: (config: {
    schemas: readonly never[]
    config?: unknown
  }) => Promise<WasmEncryptionClient>,
): EncryptionFactory {
  return (async (config: { schemas: readonly never[]; config?: unknown }) => {
    const client = await createWasmClient(config)
    const adapted = {
      encrypt: (value: unknown, opts: unknown) =>
        withUnsupportedChainers(
          (client.encrypt as (v: unknown, o: unknown) => Promise<unknown>)(
            value,
            opts,
          ),
        ),
      encryptModel: (model: unknown, table: unknown) =>
        withUnsupportedChainers(
          (client.encryptModel as (m: unknown, t: unknown) => Promise<unknown>)(
            model,
            table,
          ),
        ),
      bulkEncryptModels: (models: unknown, table: unknown) =>
        withUnsupportedChainers(
          (
            client.bulkEncryptModels as (
              m: unknown,
              t: unknown,
            ) => Promise<unknown>
          )(models, table),
        ),
      decryptModel: (model: unknown, table: unknown) =>
        withUnsupportedChainers(
          (client.decryptModel as (m: unknown, t: unknown) => Promise<unknown>)(
            model,
            table,
          ),
        ),
      bulkDecryptModels: (models: unknown, table: unknown) =>
        withUnsupportedChainers(
          (
            client.bulkDecryptModels as (
              m: unknown,
              t: unknown,
            ) => Promise<unknown>
          )(models, table),
        ),
      // `bulkEncrypt` deliberately absent — see the module comment.
    }
    return adapted
    // biome-ignore lint/plugin: the adapted object implements only the five methods the pipeline calls, deliberately (see the module comment) — it is not, and must not claim to be, a whole EncryptionClient.
  }) as unknown as EncryptionFactory
}
