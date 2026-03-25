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

  try {
    return require(pkg);
  } catch (err) {
    throw new Error(
      `Failed to load native binding for ${platform}-${arch}. ` +
        `Ensure the optional dependency "${pkg}" is installed.\n` +
        `Original error: ${err.message}`,
    );
  }
}

module.exports = loadBinding();
