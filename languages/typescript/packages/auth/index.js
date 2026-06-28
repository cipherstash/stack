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
  const failure = { type, error: err, ...payload };
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
    return fn.apply(this, args).then((data) => ({ data }), toFailure);
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

// Wrap strategy factory methods (sync, can throw)
const origDetect = native.AutoStrategy.detect;
native.AutoStrategy.detect = wrapSync(origDetect);

const origCreate = native.AccessKeyStrategy.create;
native.AccessKeyStrategy.create = wrapSync(origCreate);

const origFromProfile = native.DeviceSessionStrategy.fromProfile;
native.DeviceSessionStrategy.fromProfile = wrapSync(origFromProfile);

// napi defines class static methods as non-writable, so a factory's
// synchronously-thrown errors can't be `.code`-enriched by patching the
// native class in place. Expose a thin wrapper whose static factories run
// through `wrapSync`. Instances are the native ones — their async
// `getToken()` is already enriched via the prototype patch above.
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

// Export wrapped top-level functions alongside native re-exports
module.exports = {
  ...native,
  OidcFederationStrategy,
  // Deprecated alias: `OAuthStrategy` was renamed to `DeviceSessionStrategy`.
  // Kept so existing consumers don't break; remove in a future major.
  OAuthStrategy: native.DeviceSessionStrategy,
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
