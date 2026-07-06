// Wrapper that loads the native napi-rs module and converts its outcomes into
// the `@byteslice/result` shape: `{ data }` on success, `{ failure }` on a
// domain error. The Rust side never reaches the caller as a throw — every
// `AuthError` crosses the FFI boundary as a `__CS_FAIL__`-sentineled JSON blob
// in the rejection/throw, which we parse here into a typed `failure`. Only a
// genuine panic (no sentinel) propagates as a thrown exception.

const native = require("./stack-auth-node.js");

// Must match `FAILURE_SENTINEL` in src/lib.rs.
const FAILURE_SENTINEL = "__CS_FAIL__";

/**
 * Convert a thrown/rejected native error into a `Result` `failure`.
 *
 * Domain failures carry the sentinel + serialized `AuthError`
 * (`{ type, message, help?, url?, ...payload }`); we reuse the thrown `Error`
 * as the live `failure.error`, restoring its message and attaching the
 * structured fields. Anything without the sentinel is a real bug/panic and is
 * re-thrown unchanged.
 */
function toFailure(err) {
  if (!(err instanceof Error) || !err.message.startsWith(FAILURE_SENTINEL)) {
    throw err;
  }
  const { type, message, help, url, ...payload } = JSON.parse(
    err.message.slice(FAILURE_SENTINEL.length),
  );
  err.message = message;
  err.code = type;
  // Spread payload first so the fixed `type`/`error` keys always win, even if a
  // future payload field collides with one of them.
  const failure = { ...payload, type, error: err };
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

/**
 * Wrap an async native function so it resolves to `{ data }` / `{ failure }`
 * and never rejects for a domain error.
 */
function wrapAsync(fn) {
  return function (...args) {
    // napi argument coercion throws synchronously, before a Promise exists —
    // surface it as a rejection so a `Promise`-returning signature never
    // throws. (Coercion errors carry no sentinel, so they stay errors.)
    try {
      return fn.apply(this, args).then((data) => ({ data }), toFailure);
    } catch (err) {
      return Promise.reject(err);
    }
  };
}

/**
 * Wrap a sync native function so it returns `{ data }` / `{ failure }`.
 */
function wrapSync(fn) {
  return function (...args) {
    try {
      return { data: fn.apply(this, args) };
    } catch (err) {
      return toFailure(err);
    }
  };
}

// Patch DeviceCodeResult prototype methods
const dcProto = native.DeviceCodeResult.prototype;
dcProto.pollForToken = wrapAsync(dcProto.pollForToken);
dcProto.openInBrowser = wrapSync(dcProto.openInBrowser);

// Patch strategy getToken methods
for (const Strategy of [
  native.AutoStrategy,
  native.AccessKeyStrategy,
  native.DeviceSessionStrategy,
  native.OidcFederationStrategy,
]) {
  Strategy.prototype.getToken = wrapAsync(Strategy.prototype.getToken);
}

// napi defines class static methods as non-writable (and this file is sloppy
// mode), so the factories can't be Result-wrapped by patching the native
// class in place — the assignment silently no-ops. Each strategy instead gets
// a thin facade class whose static factories run through `wrapSync`.
// Instances are the native ones — their async `getToken()` is already
// wrapped via the prototype patch above. (Facade instances are never
// constructed, so `instanceof` against these classes is not part of the
// contract.)
// The native factory must be invoked as a method of its native class —
// napi needs the class as the receiver to construct the returned instance —
// hence the closure form rather than passing the unbound static to wrapSync.
class AutoStrategy {
  static detect(options) {
    return wrapSync(() => native.AutoStrategy.detect(options))();
  }
}

class AccessKeyStrategy {
  static create(workspaceCrn, accessKey) {
    return wrapSync(() =>
      native.AccessKeyStrategy.create(workspaceCrn, accessKey),
    )();
  }
}

class DeviceSessionStrategy {
  static fromProfile() {
    return wrapSync(() => native.DeviceSessionStrategy.fromProfile())();
  }
}

const NativeOidcFederationStrategy = native.OidcFederationStrategy;
class OidcFederationStrategy {
  static create(workspaceCrn, getJwt, baseUrl) {
    // Wrap `getJwt` so the napi binding always sees a Promise-returning
    // function even if the caller passed a sync one — the native side coerces
    // the return to `Promise<string>`. Matches the wasm wrapper (wasm-inline.mjs).
    const jwt = () => Promise.resolve(getJwt());
    return wrapSync(() =>
      NativeOidcFederationStrategy.create(workspaceCrn, jwt, baseUrl),
    )();
  }

  static createWithStore(workspaceCrn, getJwt, loadToken, saveToken, baseUrl) {
    // Same defensive wrap for all three callbacks, so sync implementations
    // (e.g. an in-memory store) work without the caller pre-wrapping them.
    const jwt = () => Promise.resolve(getJwt());
    const load = () => Promise.resolve(loadToken());
    const save = (json) => Promise.resolve(saveToken(json));
    return wrapSync(() =>
      NativeOidcFederationStrategy.createWithStore(
        workspaceCrn,
        jwt,
        load,
        save,
        baseUrl,
      ),
    )();
  }
}

// Export wrapped top-level functions alongside native re-exports. The facade
// classes shadow their native counterparts from the `...native` spread.
module.exports = {
  ...native,
  AutoStrategy,
  AccessKeyStrategy,
  DeviceSessionStrategy,
  OidcFederationStrategy,
  // Deprecated alias: `OAuthStrategy` was renamed to `DeviceSessionStrategy`.
  // Kept so existing consumers don't break; remove in a future major.
  OAuthStrategy: DeviceSessionStrategy,
  beginDeviceCodeFlow: wrapAsync(native.beginDeviceCodeFlow),
  bindClientDevice: wrapAsync(native.bindClientDevice),
};

if (native.beginDeviceCodeFlowWithBaseUrl) {
  module.exports.beginDeviceCodeFlowWithBaseUrl = wrapAsync(
    native.beginDeviceCodeFlowWithBaseUrl,
  );
}

if (native.bindClientDeviceWithProfileDir) {
  module.exports.bindClientDeviceWithProfileDir = wrapAsync(
    native.bindClientDeviceWithProfileDir,
  );
}
