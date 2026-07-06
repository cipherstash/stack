import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import { mkdtempSync, writeFileSync, copyFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// The public type surface is split across two files: `index.d.ts` is
// hand-written and re-exports the NAPI-RS–generated `native.d.ts`, adding the
// declarations napi can't emit (`AuthError`, `AuthErrorCode`, `OAuthStrategy`).
//
// vitest erases type-only imports and never runs `tsc`, so a broken split —
// the `export * from "./native"` re-export removed, the `AuthError` interface
// or `OAuthStrategy` alias deleted, `native.d.ts` failing to resolve, or a
// generated symbol no longer reaching the package entrypoint — would compile
// green through the rest of the suite while silently breaking every consumer's
// `import { ... } from "@cipherstash/auth"`.
//
// This test is the only thing that exercises the contract the way a real
// consumer does: it type-checks an importing module against the package, by
// name, through the `package.json` `exports` map. It asserts behaviour (does a
// consumer compile?) rather than grepping the declaration file for strings.

const packageDir = join(__dirname, "..");
// Run the locally-installed tsc as a script under the current node, so this is
// cross-platform (no shell, no `.bin` shim) and pinned to the devDependency.
const tscBin = require.resolve("typescript/bin/tsc");

// A consumer that imports — and *uses*, so nothing is elided — the public
// Result surface: the success types (`TokenResult`), the `AuthFailure`
// discriminated union + `AuthErrorCode`, the strategy classes (as values, to
// call their `Result`-returning factories/methods), and the `OAuthStrategy`
// runtime alias. It exercises narrowing on both arms of a `Result` and the
// per-variant `WORKSPACE_MISMATCH` payload — so a broken return type, a missing
// failure variant, or an unresolved `@byteslice/result` / `./native` re-export
// fails the typecheck.
const CONSUMER = `
import type { AuthFailure, AuthErrorCode, TokenResult } from "@cipherstash/auth";
import {
  AutoStrategy,
  DeviceSessionStrategy,
  OAuthStrategy,
} from "@cipherstash/auth";

const _alias: typeof DeviceSessionStrategy = OAuthStrategy;

function handle(failure: AuthFailure): AuthErrorCode {
  if (failure.type === "WORKSPACE_MISMATCH") {
    const _e: string = failure.expected;
    const _a: string = failure.actual;
    void _e;
    void _a;
  }
  return failure.type;
}

async function run() {
  const detected = AutoStrategy.detect();
  if (detected.failure) {
    void handle(detected.failure);
    return;
  }
  const result = await detected.data.getToken();
  if (result.failure) {
    void handle(result.failure);
  } else {
    const token: TokenResult = result.data;
    const _t: string = token.token;
    void _t;
  }
}

void run;
void _alias;
`;

// Node16 resolution makes tsc honour the package's `exports` map (the "node"
// condition resolves to `index.d.ts`), so this verifies the real entrypoint a
// consumer hits — not just a relative path into the file.
const baseCompilerOptions = {
  target: "ES2020",
  module: "Node16",
  moduleResolution: "Node16",
  strict: true,
  esModuleInterop: true,
  skipLibCheck: true,
  noEmit: true,
  baseUrl: ".",
};

// Type-check CONSUMER against whatever `@cipherstash/auth` resolves to at
// `pkgDir`. Returns whether tsc accepted it and its combined output.
function typecheckConsumerAgainst(pkgDir: string): {
  ok: boolean;
  output: string;
} {
  const dir = mkdtempSync(join(tmpdir(), "cs-auth-tscheck-"));
  writeFileSync(join(dir, "consumer.ts"), CONSUMER);
  writeFileSync(
    join(dir, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        ...baseCompilerOptions,
        paths: { "@cipherstash/auth": [pkgDir] },
      },
      files: ["consumer.ts"],
    }),
  );

  try {
    const output = execFileSync(
      process.execPath,
      [tscBin, "-p", join(dir, "tsconfig.json")],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
    return { ok: true, output };
  } catch (err) {
    const e = err as { stdout?: Buffer | string; stderr?: Buffer | string };
    return { ok: false, output: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

describe("consumer typecheck (index.d.ts -> native.d.ts split)", () => {
  it("a consumer importing from @cipherstash/auth type-checks", () => {
    const { ok, output } = typecheckConsumerAgainst(packageDir);
    expect(ok, `tsc reported type errors:\n${output}`).toBe(true);
  });

  it("rejects a consumer when the split is broken (guard has teeth)", () => {
    // Mirror the real package so module resolution is identical (same
    // package.json/`exports`), but replace index.d.ts with a stub that drops
    // the `export * from "./native"` re-export and the hand-written
    // declarations. The consumer must now fail to compile — proving this
    // harness actually goes red when the split breaks, rather than only
    // passing when everything is intact.
    const brokenPkg = mkdtempSync(join(tmpdir(), "cs-auth-broken-"));
    copyFileSync(
      join(packageDir, "package.json"),
      join(brokenPkg, "package.json"),
    );
    writeFileSync(join(brokenPkg, "index.d.ts"), "export {};\n");

    const { ok } = typecheckConsumerAgainst(brokenPkg);
    expect(ok, "tsc should reject a consumer when the split is broken").toBe(
      false,
    );
  });
});

describe("runtime re-export contract (index.js)", () => {
  it("OAuthStrategy is the same runtime value as DeviceSessionStrategy", () => {
    // The typecheck above (noEmit) only proves the *type* alias resolves. The
    // runtime alias `module.exports.OAuthStrategy = native.DeviceSessionStrategy`
    // in index.js is exercised by nothing else, so load the real entrypoint and
    // assert it: drop that line and `import { OAuthStrategy }` silently becomes
    // `undefined` for consumers.
    const mod = require("../index.js") as typeof import("../index");
    expect(mod.OAuthStrategy).toBeDefined();
    expect(mod.OAuthStrategy).toBe(mod.DeviceSessionStrategy);
  });
});

describe("publish contract (npm pack)", () => {
  it("packs the declarations required by index.d.ts", () => {
    // index.d.ts does `export * from "./native"`, so native.d.ts MUST ship in
    // the tarball or every published consumer's import dangles on a missing
    // file. The typecheck resolves against the source tree, not the packed
    // output, so this is the only guard on the `files` allowlist.
    const out = execFileSync("npm", ["pack", "--json", "--dry-run"], {
      cwd: packageDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const packed = (
      JSON.parse(out) as Array<{ files: Array<{ path: string }> }>
    )[0].files.map((f) => f.path);
    expect(packed).toEqual(
      expect.arrayContaining(["index.d.ts", "native.d.ts"]),
    );
  });

  it("bundles the LICENSE (README links to it; repo URL is private)", () => {
    // The README's license link points at the private repo, unreachable from
    // npmjs.org — so a copy must ride in the tarball. Guard the `files` entry.
    const out = execFileSync("npm", ["pack", "--json", "--dry-run"], {
      cwd: packageDir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    const packed = (
      JSON.parse(out) as Array<{ files: Array<{ path: string }> }>
    )[0].files.map((f) => f.path);
    expect(packed).toContain("LICENSE");
  });
});
