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
/** @typedef {{ store?: TokenStore; baseUrl?: string; cacheCapacity?: number }} OidcFederationStrategyOptions */

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

// A `getJwt` failure as the binding would report one (`SERVER_ERROR`, same
// message prefix), so callers cannot tell which side of the boundary the
// callback failed on.
function getJwtFailure(detail) {
  const err = new Error(`getJwt ${detail}`);
  err.__authFailure = { type: "SERVER_ERROR", message: err.message };
  return toFailure(err);
}

// Mirror index.js's `wrapAsync`: a synchronous throw from the inner `getToken`
// (e.g. calling it after `free()` — "null pointer passed to rust") becomes a
// rejection, so a Promise-returning method never throws synchronously.
function settleGetToken(inner) {
  try {
    return inner.getToken().then((data) => ({ data }), toFailure);
  } catch (err) {
    return Promise.reject(err);
  }
}

export class AccessKeyStrategy {
  #inner;

  // Ambient strategy: the credential is a static value readable anywhere, so
  // `getToken()` self-refreshes and consumers can drive it directly.
  requiresFederation = false;

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
    return settleGetToken(this.#inner);
  }

  free() {
    this.#inner.free();
  }
}

export class OidcFederationStrategy {
  #inner;
  /** @type {OidcProvider} */
  #getJwt;

  // Federated strategy: the third-party JWT lives in request scope and the
  // cache is request-scoped, so federation must happen in scope. Consumers
  // should read a warmed token (see `@cipherstash/auth/next`) rather than drive
  // `getToken()` from a detached context.
  requiresFederation = true;

  /**
   * @param {RawOidcFederationStrategy} inner
   * @param {OidcProvider} getJwt
   */
  constructor(inner, getJwt) {
    this.#inner = inner;
    this.#getJwt = getJwt;
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
      const cacheCapacity = options?.cacheCapacity;
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
              cacheCapacity,
            ),
            getJwt,
          ),
        };
      }
      return {
        data: new OidcFederationStrategy(
          RawOidcFederationStrategy.create(
            workspaceCrn,
            jwt,
            baseUrl,
            cacheCapacity,
          ),
          getJwt,
        ),
      };
    } catch (err) {
      return toFailure(err);
    }
  }

  /**
   * Calls `getJwt` here, in the caller's async context, and hands the JWT to
   * the binding's `getTokenForJwt` — the same split as the Node entry
   * (index.js), so a `getJwt` that reads the request from an async-context
   * store works the same way on both. The binding's own `getToken()` would
   * call `getJwt` from inside the wasm future instead.
   *
   * @returns {Promise<import("./wasm-inline.d.ts").GetTokenResult>}
   */
  async getToken() {
    let jwt;
    try {
      jwt = await this.#getJwt();
    } catch (err) {
      return getJwtFailure(
        `rejected: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    if (typeof jwt !== "string") {
      return getJwtFailure("callback did not return a string");
    }
    return this.getTokenForJwt(jwt);
  }

  /**
   * The CTS token for `jwt`, the caller's own provider JWT: `getToken()`
   * minus the `getJwt` call, sharing its cache.
   *
   * @param {string} jwt
   * @returns {Promise<import("./wasm-inline.d.ts").GetTokenResult>}
   */
  getTokenForJwt(jwt) {
    try {
      return this.#inner
        .getTokenForJwt(jwt)
        .then((data) => ({ data }), toFailure);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  free() {
    this.#inner.free();
  }
}
