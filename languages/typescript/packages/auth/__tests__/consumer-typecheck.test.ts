import { describe, it, expect } from "vitest";
import { execFileSync } from "child_process";
import { mkdtempSync, writeFileSync } from "fs";
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

// A consumer that imports — and *uses*, so nothing is elided — every symbol
// that has to survive the split: the napi-generated classes/interfaces re-
// exported via `./native`, the hand-written `AuthError`/`AuthErrorCode`, and
// the `OAuthStrategy` runtime alias (imported as a value, not a type).
const CONSUMER = `
import type {
  AuthError,
  AuthErrorCode,
  TokenResult,
  DeviceSessionStrategy,
  AutoStrategy,
} from "@cipherstash/auth";
import { OAuthStrategy } from "@cipherstash/auth";

const _alias: typeof DeviceSessionStrategy = OAuthStrategy;

function codeOf(err: AuthError): AuthErrorCode {
  return err.code;
}

declare const tr: TokenResult;
const _token: string = tr.token;
declare const auto: AutoStrategy;

void codeOf;
void _alias;
void _token;
void auto;
`;

// Node16 resolution makes tsc honour the package's `exports` map (the "node"
// condition resolves to `index.d.ts`), so this verifies the real entrypoint a
// consumer hits — not just a relative path into the file.
const tsconfig = {
  compilerOptions: {
    target: "ES2020",
    module: "Node16",
    moduleResolution: "Node16",
    strict: true,
    esModuleInterop: true,
    skipLibCheck: true,
    noEmit: true,
    baseUrl: ".",
    paths: { "@cipherstash/auth": [packageDir] },
  },
  files: ["consumer.ts"],
};

describe("consumer typecheck (index.d.ts -> native.d.ts split)", () => {
  it("a consumer importing from @cipherstash/auth type-checks", () => {
    const dir = mkdtempSync(join(tmpdir(), "cs-auth-tscheck-"));
    writeFileSync(join(dir, "consumer.ts"), CONSUMER);
    writeFileSync(join(dir, "tsconfig.json"), JSON.stringify(tsconfig));

    let output = "";
    let ok = true;
    try {
      output = execFileSync(
        process.execPath,
        [tscBin, "-p", join(dir, "tsconfig.json")],
        { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      );
    } catch (err) {
      ok = false;
      const e = err as { stdout?: Buffer | string; stderr?: Buffer | string };
      output = `${e.stdout ?? ""}${e.stderr ?? ""}`;
    }

    expect(ok, `tsc reported type errors:\n${output}`).toBe(true);
  });
});
