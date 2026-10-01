/* eslint-disable no-console */
// Native binding loader for @cipherstash/auth
// Resolves the correct platform-specific optional dependency package.

const { platform, arch } = process;

function isMusl() {
  try {
    // If dlopen is available, check if the libc is musl
    const report =
      typeof process.report?.getReport === "function"
        ? process.report.getReport()
        : null;
    if (report && typeof report === "object" && report.sharedObjects) {
      return report.sharedObjects.some((s) => s.includes("musl"));
    }
  } catch (_) {
    // Fallback: check if /usr/bin/ldd mentions musl
  }
  try {
    const { execSync } = require("node:child_process");
    return execSync("ldd --version 2>&1", { encoding: "utf8" }).includes(
      "musl",
    );
  } catch (_) {
    return false;
  }
}

const platforms = {
  "darwin-x64": "@cipherstash/auth-darwin-x64",
  "darwin-arm64": "@cipherstash/auth-darwin-arm64",
  "linux-x64-gnu": "@cipherstash/auth-linux-x64-gnu",
  "linux-x64-musl": "@cipherstash/auth-linux-x64-musl",
  "linux-arm64-gnu": "@cipherstash/auth-linux-arm64-gnu",
  "win32-x64-msvc": "@cipherstash/auth-win32-x64-msvc",
};

function loadBinding() {
  let key = `${platform}-${arch}`;

  if (platform === "linux") {
    key += isMusl() ? "-musl" : "-gnu";
  } else if (platform === "win32") {
    key += "-msvc";
  }

  const pkg = platforms[key];
  if (!pkg) {
    throw new Error(
      `Unsupported platform: ${platform}-${arch}. ` +
        `@cipherstash/auth supports: ${Object.keys(platforms).join(", ")}`,
    );
  }

  // Prefer a local .node binary (local development / napi build) so that
  // locally-built features (e.g. test-utils) take priority over a published
  // platform package that may have been installed alongside it.
  try {
    return require("./stack-auth-node.node");
  } catch (_) {}

  // Fall back to the platform-specific optional dependency (production / npm install)
  try {
    return require(pkg);
  } catch (_) {}

  throw new Error(
    `Failed to load native binding for ${platform}-${arch}. ` +
      `Ensure the optional dependency "${pkg}" is installed, ` +
      `or run "napi build" for local development.`,
  );
}

module.exports = loadBinding();
