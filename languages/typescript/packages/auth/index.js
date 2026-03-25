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
const proto = native.DeviceCodeResult.prototype;
proto.pollForToken = wrapAsync(proto.pollForToken);
proto.openInBrowser = wrapSync(proto.openInBrowser);

// Export wrapped top-level functions alongside native re-exports
module.exports = {
  ...native,
  beginDeviceCodeFlow: wrapAsync(native.beginDeviceCodeFlow),
};

if (native.beginDeviceCodeFlowWithBaseUrl) {
  module.exports.beginDeviceCodeFlowWithBaseUrl = wrapAsync(
    native.beginDeviceCodeFlowWithBaseUrl,
  );
}
