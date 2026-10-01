const { platform, arch } = process;

function isMusl() {
  try {
    const report =
      typeof process.report?.getReport === "function"
        ? process.report.getReport()
        : null;
    if (report && typeof report === "object" && report.sharedObjects) {
      return report.sharedObjects.some((s) => s.includes("musl"));
    }
  } catch (_) {}
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
  "darwin-x64": "@cipherstash/profile-darwin-x64",
  "darwin-arm64": "@cipherstash/profile-darwin-arm64",
  "linux-x64-gnu": "@cipherstash/profile-linux-x64-gnu",
  "linux-x64-musl": "@cipherstash/profile-linux-x64-musl",
  "linux-arm64-gnu": "@cipherstash/profile-linux-arm64-gnu",
  "win32-x64-msvc": "@cipherstash/profile-win32-x64-msvc",
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
        `@cipherstash/profile supports: ${Object.keys(platforms).join(", ")}`,
    );
  }

  // Prefer local .node binary (development / napi build)
  try {
    return require("./stack-profile-node.node");
  } catch (_) {}

  // Fall back to platform-specific optional dependency
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
