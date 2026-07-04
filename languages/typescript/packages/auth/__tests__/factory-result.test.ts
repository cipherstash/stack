import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// Runtime coverage for the sync strategy factories through index.js. napi
// defines class statics as non-writable, so a Result-wrapping bug there is
// invisible to both the Rust tests (which test the native layer directly) and
// the compile-only consumer-typecheck test — the factories must be exercised
// at runtime, on both arms, via the public entry point.
const {
  AutoStrategy,
  AccessKeyStrategy,
  DeviceSessionStrategy,
  OAuthStrategy,
} = require("../index.js") as typeof import("../index");

const VALID_CRN = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY";
// Well-formed key (`CSAK<key-id>.<secret>`) — factories only parse the shape;
// no network call happens until getToken().
const VALID_KEY = "CSAKtestKeyId.testKeySecret";

const SAVED_ENV_KEYS = [
  "CS_CLIENT_ACCESS_KEY",
  "CS_WORKSPACE_CRN",
  "CS_CONFIG_PATH",
] as const;
let savedEnv: Partial<Record<(typeof SAVED_ENV_KEYS)[number], string>>;

beforeEach(() => {
  savedEnv = {};
  for (const key of SAVED_ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  // Point the profile store at an empty temp dir so ambient ~/.cipherstash
  // state can't leak into detection.
  process.env.CS_CONFIG_PATH = mkdtempSync(join(tmpdir(), "cs-auth-test-"));
});

afterEach(() => {
  for (const key of SAVED_ENV_KEYS) {
    if (savedEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = savedEnv[key];
    }
  }
});

describe("AccessKeyStrategy.create", () => {
  it("returns a failure for a malformed CRN", () => {
    const r = AccessKeyStrategy.create("not-a-crn", VALID_KEY);
    expect(r.failure?.type).toBe("INVALID_CRN");
    expect(r.failure?.error).toBeInstanceOf(Error);
    // The FFI sentinel must be stripped from the surfaced message.
    expect(r.failure?.error.message).not.toContain("__CS_FAIL__");
  });

  it("returns a failure for a malformed access key", () => {
    const r = AccessKeyStrategy.create(VALID_CRN, "not-a-key");
    expect(r.failure?.type).toBe("INVALID_ACCESS_KEY");
  });

  it("returns { data } wrapping a usable strategy on success", () => {
    const r = AccessKeyStrategy.create(VALID_CRN, VALID_KEY);
    if (r.failure) {
      expect.unreachable(`create failed: ${r.failure.type}`);
    }
    // A bare (unwrapped) native instance would have no `data` key — this
    // assertion is what distinguishes a wrapped Result from the native value.
    expect(typeof r.data.getToken).toBe("function");
  });
});

describe("AutoStrategy.detect", () => {
  it("returns a NOT_AUTHENTICATED failure when no credentials exist", () => {
    const r = AutoStrategy.detect();
    expect(r.failure?.type).toBe("NOT_AUTHENTICATED");
    expect(r.failure?.help).toBeTruthy();
  });

  it("returns a MISSING_WORKSPACE_CRN failure for an access key without a CRN", () => {
    const r = AutoStrategy.detect({ accessKey: VALID_KEY });
    expect(r.failure?.type).toBe("MISSING_WORKSPACE_CRN");
  });

  it("returns { data } wrapping a usable strategy for explicit options", () => {
    const r = AutoStrategy.detect({
      accessKey: VALID_KEY,
      workspaceCrn: VALID_CRN,
    });
    if (r.failure) {
      expect.unreachable(`detect failed: ${r.failure.type}`);
    }
    expect(typeof r.data.getToken).toBe("function");
  });
});

describe("DeviceSessionStrategy.fromProfile", () => {
  it("returns a STORE_ERROR failure when the profile store is empty", () => {
    const r = DeviceSessionStrategy.fromProfile();
    expect(r.failure?.type).toBe("STORE_ERROR");
    expect(r.failure?.error).toBeInstanceOf(Error);
  });

  it("is what the deprecated OAuthStrategy alias points at", () => {
    expect(OAuthStrategy).toBe(DeviceSessionStrategy);
  });
});
