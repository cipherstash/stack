import { describe, it, expect } from "vitest";
import { existsSync } from "fs";
import { join } from "path";

// JS-level coverage of `wasm-inline.mjs`'s `toFailure` — the seam that turns
// the wasm binding's branded `__authFailure` object into a `Result` failure.
// The Rust side of the brand is pinned by the wasm-bindgen test
// `to_js_error_attaches_auth_failure_object_with_payload_and_help`; this file
// pins the JS side: envelope fields surface on the failure, and the internal
// `message` field is stripped rather than leaking as a spread field.
//
// The wasm artifacts are gitignored (`npm run build:wasm` produces them), and
// the vitest CI job builds only the napi module — so these tests self-skip
// when the shim is absent. They run locally after a wasm build.
const WASM_SHIM = join(__dirname, "..", "wasm", "stack_auth_wasm_inline.js");

describe.skipIf(!existsSync(WASM_SHIM))("wasm-inline Result wrapper", () => {
  const VALID_CRN = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY";
  const VALID_KEY = "CSAKtestKeyId.testKeySecret";

  async function loadWasmInline() {
    // Dynamic import: a static one would fail module resolution when the
    // gitignored artifacts are absent, even with the describe skipped.
    return import("../wasm-inline.mjs");
  }

  it("converts a branded wasm error into a typed failure with help", async () => {
    const { AccessKeyStrategy } = await loadWasmInline();
    const r = AccessKeyStrategy.create("not-a-crn", VALID_KEY);
    expect(r.failure?.type).toBe("INVALID_CRN");
    expect(r.failure?.error).toBeInstanceOf(Error);
    // help from the serialized envelope must surface on the failure.
    expect(r.failure?.help).toMatch(/crn:<region>:<workspace-id>/);
  });

  it("strips the envelope's message field instead of spreading it", async () => {
    const { AccessKeyStrategy } = await loadWasmInline();
    const r = AccessKeyStrategy.create("not-a-crn", VALID_KEY);
    if (!r.failure) {
      expect.unreachable("create should fail for a malformed CRN");
    }
    // `message` rides in `__authFailure` for the Rust-side envelope tests but
    // is internal here — the live Error already carries it. A regression in
    // the `delete payload.message` line would spread it onto the failure.
    expect("message" in r.failure).toBe(false);
    expect(r.failure.error.message).toContain("Invalid workspace CRN");
  });

  it("returns { data } wrapping a usable strategy on success", async () => {
    const { AccessKeyStrategy } = await loadWasmInline();
    const r = AccessKeyStrategy.create(VALID_CRN, VALID_KEY);
    if (r.failure) {
      expect.unreachable(`create failed: ${r.failure.type}`);
    }
    expect(typeof r.data.getToken).toBe("function");
    r.data.free();
  });
});
