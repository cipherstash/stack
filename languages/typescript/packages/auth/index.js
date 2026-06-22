// Wrapper that loads the native napi-rs module and enriches errors with a
// machine-readable `.code` property by parsing the "CODE: message" format
// that the Rust side produces.

const native = require("./stack-auth-node.js");

const CODE_RE = /^([A-Z_]+): /;

/**
 * Parse the "CODE: message" format produced by the Rust bindings and attach
 * `.code` to the Error object.
 */
function enrichError(err) {
  if (err instanceof Error) {
    const match = CODE_RE.exec(err.message);
    if (match) {
      err.code = match[1];
      err.message = err.message.slice(match[0].length);
    }
  }
  throw err;
}

/**
 * Wrap an async function so that rejected errors get `.code` enrichment.
 */
function wrapAsync(fn) {
  return function (...args) {
    return fn.apply(this, args).catch(enrichError);
  };
}

/**
 * Wrap a sync function so that thrown errors get `.code` enrichment.
 */
function wrapSync(fn) {
  return function (...args) {
    try {
      return fn.apply(this, args);
    } catch (err) {
      enrichError(err);
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
