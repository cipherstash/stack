import { withEnvCredentials } from './credentials.js'
import type { AuthStrategy, ClientOpts, EncryptConfig } from './types.js'
import type { NewClientOptions } from './types.js'

/**
 * The options object the addon actually receives — `NewClientOptions` minus the
 * auth strategy, which travels separately.
 *
 * Takes the public {@link EncryptConfig} unchanged. Vocabulary normalisation
 * (`cast_as: 'string'` → `'text'`, the `ste_vec` array-index-mode default)
 * used to happen here in JS; it now runs inside the Rust at the
 * deserialization boundary, so BOTH bindings accept the public spellings and
 * there is one implementation rather than one per entry point. See
 * `crates/protect-ffi/src/encrypt_config.rs`.
 */
export type NativeNewClientOptions = {
  encryptConfig: EncryptConfig
  clientOpts?: ClientOpts
  eqlVersion?: 2 | 3
}

/**
 * Throw naming the option key `JSON.stringify` chokes on, before neon does it
 * anonymously.
 *
 * Forwarding what this layer doesn't handle is what lets Rust reject an unknown
 * key by name (#144) — but it also means an unknown key now reaches neon's
 * `Json` extractor, which is `JSON.stringify`. A circular value or a `bigint`
 * throws there, before serde runs, and the `TypeError` says only `Converting
 * circular structure to JSON`. `newClient({...appConfig, logger})` is the shape
 * that hits it, and on a change whose point is naming the offender that is the
 * wrong failure.
 *
 * Only the forwarded keys are checked. `clientOpts` and the auth strategy are
 * handled above and never reach here, and a circular `encryptConfig` fails the
 * same way it always has — this covers exactly what forwarding newly exposed,
 * for the cost of one `JSON.stringify` of the config at client construction.
 *
 * A key whose value is a function or a symbol is NOT caught: `JSON.stringify`
 * drops those without throwing, so they stay a silent drop on this binding
 * while wasm rejects them. That asymmetry is in the CHANGELOG.
 *
 * Interim. #150 replaces this whole error layer with codes derived in Rust.
 */
function nameTheKeyJsonCannotCarry(rest: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(rest)) {
    try {
      JSON.stringify(value)
    } catch (cause) {
      throw new Error(
        `newClient option \`${key}\` cannot be sent to the addon: ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
        { cause },
      )
    }
  }
}

/**
 * Split `newClient`'s options into the two arguments the addon takes.
 *
 * The strategy cannot ride along inside the options object: neon's `Json`
 * extractor is `JSON.stringify`-based, which drops functions, so the addon
 * takes it as a separate `Root<JsObject>` argument. The wasm entry solves the
 * same problem by pulling it off with `Reflect::get` before serde runs.
 *
 * Its own module, rather than inline in `index.cts`, so it is reachable from a
 * unit test — vitest cannot transform `.cts`, and the alternative is an
 * integration test that needs real credentials to reach the line under test.
 */
export function newClientArgs(
  opts: NewClientOptions,
): [NativeNewClientOptions, AuthStrategy | undefined] {
  // Pull out only what this layer has to handle — the auth strategy and
  // `clientOpts` (credentials are filled in from env here). Everything else is
  // forwarded verbatim rather than re-listed field by field, so a key the Rust
  // doesn't recognise reaches serde and is rejected by name instead of being
  // quietly dropped on the way through. The wasm entry rejects the same input
  // the same way.
  const { authStrategy, strategy, clientOpts, ...rest } = opts
  nameTheKeyJsonCannotCarry(rest)
  return [
    { ...rest, clientOpts: withEnvCredentials(clientOpts) },
    // `strategy` is the old name for `authStrategy`, kept working while it is
    // deprecated. The new name wins when both are set — a rename is only safe
    // if it does, or a caller mid-migration passing both silently keeps the old
    // object.
    authStrategy ?? strategy,
  ]
}
