/* @ts-self-types="./wasm-inline.d.ts" */

// Slick wrapper around the wasm-bindgen-generated inline-bytes shim. The raw
// `createWithStore(workspaceCrn, key, loadFn, saveFn)` factory below is
// replaced here with a single `create(workspaceCrn, key, { store })` shape
// — easier to extend with future options (lifecycle hooks, custom logging,
// etc.) without breaking callers, and matches the options-object pattern
// most modern JS APIs use.

import { AccessKeyStrategy as RawAccessKeyStrategy } from "./wasm/stack_auth_wasm_inline.js";

/** @typedef {{ load(): Promise<string | null | undefined>; save(json: string): Promise<void> }} TokenStore */
/** @typedef {{ store?: TokenStore }} AccessKeyStrategyOptions */

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
   * @returns {AccessKeyStrategy}
   */
  static create(workspaceCrn, accessKey, options) {
    const store = options?.store;
    if (store) {
      // Wrap the user's `load` / `save` so the wasm binding always sees
      // Promise-returning functions even if the caller passed sync ones —
      // `js_sys::Promise::from` on the wasm side casts the return value as
      // a Promise unconditionally, so sync values would otherwise reject.
      const load = () => Promise.resolve(store.load());
      const save = (/** @type {string} */ json) =>
        Promise.resolve(store.save(json));
      return new AccessKeyStrategy(
        RawAccessKeyStrategy.createWithStore(workspaceCrn, accessKey, load, save),
      );
    }
    return new AccessKeyStrategy(RawAccessKeyStrategy.create(workspaceCrn, accessKey));
  }

  /** @returns {Promise<import("./wasm-inline.d.ts").TokenResult>} */
  getToken() {
    return this.#inner.getToken();
  }

  free() {
    this.#inner.free();
  }
}
