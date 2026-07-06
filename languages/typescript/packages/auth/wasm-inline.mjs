/* @ts-self-types="./wasm-inline.d.ts" */

// Slick wrapper around the wasm-bindgen-generated inline-bytes shim. The raw
// `createWithStore(workspaceCrn, key, loadFn, saveFn)` factory below is
// replaced here with a single `create(workspaceCrn, key, { store })` shape
// — easier to extend with future options (lifecycle hooks, custom logging,
// etc.) without breaking callers, and matches the options-object pattern
// most modern JS APIs use.

import {
  AccessKeyStrategy as RawAccessKeyStrategy,
  OidcFederationStrategy as RawOidcFederationStrategy,
} from "./wasm/stack_auth_wasm_inline.js";

/** @typedef {{ load(): Promise<string | null | undefined>; save(json: string): Promise<void> }} TokenStore */
/** @typedef {{ store?: TokenStore }} AccessKeyStrategyOptions */
/** @typedef {() => string | Promise<string>} OidcProvider */
/** @typedef {{ store?: TokenStore; baseUrl?: string }} OidcFederationStrategyOptions */

// Convert a thrown/rejected wasm error into a `Result` `failure`. The wasm
// binding attaches the serialized `AuthError` as an `__authFailure` object on
// the thrown `Error`; we reuse that `Error` as the live `failure.error`.
// Anything without the brand is a genuine panic and is re-thrown.
function toFailure(err) {
  const details = err && err.__authFailure;
  if (!details || typeof details.type !== "string") throw err;
  const { type, help, url, ...payload } = details;
  // `payload` still carries `message`; drop it from the spread fields.
  delete payload.message;
  // Spread payload first so the fixed `type`/`error` keys always win, even if a
  // future payload field collides with one of them.
  const failure = { ...payload, type, error: err };
  // Mirror help/url onto both the failure and the live Error, matching the napi
  // seam (index.js) — loggers that only see `failure.error` still get the hint.
  if (help !== undefined) {
    err.help = help;
    failure.help = help;
  }
  if (url !== undefined) {
    err.url = url;
    failure.url = url;
  }
  return { failure };
}

export class AccessKeyStrategy {
  #inner;

  /** @param {RawAccessKeyStrategy} inner */
  constructor(inner) {
    this.#inner = inner;
  }

  /**
   * @param {string} workspaceCrn
   * @param {string} accessKey
   * @param {AccessKeyStrategyOptions} [options]
   * @returns {import("@byteslice/result").Result<AccessKeyStrategy, import("./wasm-inline.d.ts").AuthFailure>}
   */
  static create(workspaceCrn, accessKey, options) {
    try {
      const store = options?.store;
      if (store) {
        // Wrap the user's `load` / `save` so the wasm binding always sees
        // Promise-returning functions even if the caller passed sync ones —
        // `js_sys::Promise::from` on the wasm side casts the return value as
        // a Promise unconditionally, so sync values would otherwise reject.
        const load = () => Promise.resolve(store.load());
        const save = (/** @type {string} */ json) =>
          Promise.resolve(store.save(json));
        return {
          data: new AccessKeyStrategy(
            RawAccessKeyStrategy.createWithStore(
              workspaceCrn,
              accessKey,
              load,
              save,
            ),
          ),
        };
      }
      return {
        data: new AccessKeyStrategy(
          RawAccessKeyStrategy.create(workspaceCrn, accessKey),
        ),
      };
    } catch (err) {
      return toFailure(err);
    }
  }

  /** @returns {Promise<import("./wasm-inline.d.ts").GetTokenResult>} */
  getToken() {
    return this.#inner.getToken().then((data) => ({ data }), toFailure);
  }

  free() {
    this.#inner.free();
  }
}

export class OidcFederationStrategy {
  #inner;

  /** @param {RawOidcFederationStrategy} inner */
  constructor(inner) {
    this.#inner = inner;
  }

  /**
   * @param {string} workspaceCrn
   * @param {OidcProvider} getJwt
   * @param {OidcFederationStrategyOptions} [options]
   * @returns {import("@byteslice/result").Result<OidcFederationStrategy, import("./wasm-inline.d.ts").AuthFailure>}
   */
  static create(workspaceCrn, getJwt, options) {
    try {
      // Wrap `getJwt` so the wasm binding always sees a Promise-returning
      // function even if the caller passed a sync one — see the note in
      // `AccessKeyStrategy.create`.
      const jwt = () => Promise.resolve(getJwt());
      const store = options?.store;
      const baseUrl = options?.baseUrl;
      if (store) {
        const load = () => Promise.resolve(store.load());
        const save = (/** @type {string} */ json) =>
          Promise.resolve(store.save(json));
        return {
          data: new OidcFederationStrategy(
            RawOidcFederationStrategy.createWithStore(
              workspaceCrn,
              jwt,
              load,
              save,
              baseUrl,
            ),
          ),
        };
      }
      return {
        data: new OidcFederationStrategy(
          RawOidcFederationStrategy.create(workspaceCrn, jwt, baseUrl),
        ),
      };
    } catch (err) {
      return toFailure(err);
    }
  }

  /** @returns {Promise<import("./wasm-inline.d.ts").GetTokenResult>} */
  getToken() {
    return this.#inner.getToken().then((data) => ({ data }), toFailure);
  }

  free() {
    this.#inner.free();
  }
}
