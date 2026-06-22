#!/usr/bin/env node
//
// Re-apply the hand-curated additions to the NAPI-RS-generated `index.d.ts`,
// and normalise it to the canonical *published* type surface.
//
// `napi build` regenerates `index.d.ts` from scratch on every run. That has two
// consequences this script exists to undo:
//
//   1. It drops declarations NAPI-RS can't know about — the `AuthError` /
//      `AuthErrorCode` error-enrichment types (errors are tagged with a `.code`
//      at runtime by `index.js`) and the deprecated `OAuthStrategy` alias
//      (exported at runtime as `module.exports.OAuthStrategy`). Without these,
//      consumers doing `import type { AuthError } from "@cipherstash/auth"`
//      stop compiling even though the runtime values still exist.
//
//   2. When built with `--features test-utils` (i.e. `npm run build:test`), it
//      ALSO emits test-only exports (`MockAuthServer`, `beginDeviceCodeFlow-
//      WithBaseUrl`, `bindClientDeviceWithProfileDir`, `saveTestToken`). Those
//      are gated out of release builds, so they must not appear in the
//      published `.d.ts`. Tests type them via `test-utils.d.ts` and inline
//      intersection casts instead — never from `index.d.ts`.
//
// Running this after every build makes the committed/published `index.d.ts`
// deterministic regardless of which build mode produced it. It is idempotent:
// safe to run repeatedly, a no-op on an already-normalised file.
//
// Wired into the `build`, `build:debug`, and `build:test` npm scripts.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
// Optional path arg (used by tests); `resolve` honours both absolute and
// cwd-relative inputs. Defaults to the package's own `index.d.ts`.
const dtsPath = process.argv[2]
  ? resolve(process.argv[2])
  : join(packageRoot, "index.d.ts");

const BEGIN_MARKER =
  "// --- BEGIN manual additions (scripts/apply-dts-additions.mjs) ---";
const END_MARKER = "// --- END manual additions ---";

// The curated block. `AuthErrorCode` mirrors `AuthError::error_code()` in
// `packages/stack-auth/src/lib.rs` (plus `UNKNOWN_ERROR`, the `index.js`
// fallback when a thrown error carries no recognised code). Keep in sync if a
// new `AuthError` variant is added.
const MANUAL_ADDITIONS = `${BEGIN_MARKER}
//
// Re-applied after every \`napi build\` by scripts/apply-dts-additions.mjs —
// NAPI-RS does not emit these. Edit them there, not here.

/** Error codes attached to errors thrown by this package. */
export type AuthErrorCode =
  | 'REQUEST_ERROR'
  | 'ACCESS_DENIED'
  | 'EXPIRED_TOKEN'
  | 'INVALID_GRANT'
  | 'INVALID_CLIENT'
  | 'INVALID_URL'
  | 'INVALID_REGION'
  | 'INVALID_TOKEN'
  | 'SERVER_ERROR'
  | 'STORE_ERROR'
  | 'NOT_AUTHENTICATED'
  | 'MISSING_WORKSPACE_CRN'
  | 'INVALID_ACCESS_KEY'
  | 'INVALID_CRN'
  | 'WORKSPACE_MISMATCH'
  | 'INVALID_WORKSPACE_ID'
  | 'UNKNOWN_ERROR'

/** An error thrown by this package, enriched with a machine-readable \`.code\`. */
export interface AuthError extends Error {
  code: AuthErrorCode
}

/**
 * Deprecated alias for {@link DeviceSessionStrategy}, exported at runtime as
 * \`module.exports.OAuthStrategy = DeviceSessionStrategy\`. Kept so existing
 * consumers don't break; will be removed in a future major release.
 *
 * @deprecated Renamed to \`DeviceSessionStrategy\`.
 */
export declare const OAuthStrategy: typeof DeviceSessionStrategy
${END_MARKER}`;

// Test-only exports that `--features test-utils` emits but that must never ship
// in the published surface. `function` entries are single-line in NAPI-RS
// output; `class` entries span a brace-balanced block.
const TEST_UTILS_FUNCTIONS = [
  "beginDeviceCodeFlowWithBaseUrl",
  "bindClientDeviceWithProfileDir",
  "saveTestToken",
];
const TEST_UTILS_CLASSES = ["MockAuthServer"];

/** Drop a previously-applied manual block (between the markers) so we can
 *  re-add a current copy — keeps the script idempotent. */
function stripManualBlock(src) {
  const begin = src.indexOf(BEGIN_MARKER);
  if (begin === -1) return src;
  const end = src.indexOf(END_MARKER, begin);
  if (end === -1) return src; // malformed — leave untouched rather than corrupt
  const before = src.slice(0, begin).replace(/\n+$/, "\n");
  const after = src.slice(end + END_MARKER.length).replace(/^\n+/, "");
  return after ? `${before}${after}` : before;
}

/** Number of `{` minus `}` in a line, ignoring that this is a coarse count —
 *  NAPI-RS output has no braces in strings/comments on declaration lines. */
function braceDelta(line) {
  const open = (line.match(/{/g) || []).length;
  const close = (line.match(/}/g) || []).length;
  return open - close;
}

/** Remove a `export declare {function,class} <name>` declaration and the JSDoc
 *  comment immediately preceding it. Tolerant: a name that isn't present (e.g.
 *  a release build that never emitted it) is simply skipped. */
function stripDeclaration(lines, name, kind) {
  const head =
    kind === "class"
      ? `export declare class ${name} `
      : `export declare function ${name}(`;
  const idx = lines.findIndex((l) => l.startsWith(head));
  if (idx === -1) return lines;

  // Find the end of the declaration.
  let end = idx;
  if (kind === "class") {
    let depth = braceDelta(lines[idx]);
    while (depth > 0 && end + 1 < lines.length) {
      end += 1;
      depth += braceDelta(lines[end]);
    }
  }

  // Absorb a contiguous JSDoc block directly above the declaration.
  let start = idx;
  if (start > 0 && lines[start - 1].trim().endsWith("*/")) {
    let j = start - 1;
    while (j >= 0 && !lines[j].trim().startsWith("/**")) j -= 1;
    if (j >= 0) start = j;
  }

  lines.splice(start, end - start + 1);
  return lines;
}

function normalise(src) {
  let out = stripManualBlock(src);

  let lines = out.split("\n");
  for (const fn of TEST_UTILS_FUNCTIONS)
    lines = stripDeclaration(lines, fn, "function");
  for (const cls of TEST_UTILS_CLASSES)
    lines = stripDeclaration(lines, cls, "class");
  out = lines.join("\n");

  // Collapse any blank-line runs the deletions left behind.
  out = out.replace(/\n{3,}/g, "\n\n");

  // Note the manual additions in the header banner (best-effort).
  out = out.replace(
    "/* auto-generated by NAPI-RS */",
    "/* auto-generated by NAPI-RS, with manual additions (scripts/apply-dts-additions.mjs) */",
  );

  return `${out.replace(/\n+$/, "")}\n\n${MANUAL_ADDITIONS}\n`;
}

const original = readFileSync(dtsPath, "utf8");
const updated = normalise(original);
if (updated !== original) {
  writeFileSync(dtsPath, updated);
  console.log(`apply-dts-additions: updated ${dtsPath}`);
} else {
  console.log(`apply-dts-additions: ${dtsPath} already normalised`);
}
