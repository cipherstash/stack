import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { MockAuthServer as MockAuthServerType } from "../test-utils";
import type { AuthError } from "../index";

// Load the CJS module — includes MockAuthServer when built with test-utils.
const mod = require("../index.js") as typeof import("../index") & {
  MockAuthServer: typeof MockAuthServerType;
};

const { OidcFederationStrategy, MockAuthServer } = mod;

const WORKSPACE_ID = "ZVATKW3VHMFG27DY";
const WORKSPACE_CRN = `crn:ap-southeast-2.aws:${WORKSPACE_ID}`;

let server: InstanceType<typeof MockAuthServerType>;
let savedHost: string | undefined;

beforeEach(async () => {
  server = await MockAuthServer.start();
  // OidcFederationStrategy reads the CTS base URL from CS_CTS_HOST at runtime,
  // so set it before constructing the strategy.
  savedHost = process.env.CS_CTS_HOST;
  process.env.CS_CTS_HOST = server.baseUrl;
});

afterEach(() => {
  if (savedHost === undefined) {
    delete process.env.CS_CTS_HOST;
  } else {
    process.env.CS_CTS_HOST = savedHost;
  }
});

/** A `getJwt` callback that counts invocations and returns a fixed JWT. */
function countingJwt() {
  let calls = 0;
  return {
    calls: () => calls,
    getJwt: () => {
      calls += 1;
      return Promise.resolve("header.payload.signature");
    },
  };
}

/** An in-memory `{ load, save }` token store dealing in JSON strings. */
function memStore() {
  let saved: string | null = null;
  return {
    saved: () => saved,
    load: () => Promise.resolve(saved),
    save: (json: string) => {
      saved = json;
      return Promise.resolve();
    },
  };
}

describe("OidcFederationStrategy (TypeScript / vitest)", () => {
  it("federates a third-party JWT into a CTS service token", async () => {
    server.mockAuthorizeEndpoint();
    const jwt = countingJwt();
    const strategy = OidcFederationStrategy.create(WORKSPACE_CRN, jwt.getJwt);

    const result = await strategy.getToken();

    expect(result.token).not.toBe("");
    expect(result.workspaceId).toBe(WORKSPACE_ID);
    expect(jwt.calls()).toBe(1);
  });

  it("re-federates after the cached token expires", async () => {
    // expiry 0 → the federated token is immediately expired, so the second
    // getToken() must re-federate rather than serve a cached token.
    server.mockAuthorizeEndpoint(0);
    server.mockAuthorizeEndpoint(0);
    const jwt = countingJwt();
    const strategy = OidcFederationStrategy.create(WORKSPACE_CRN, jwt.getJwt);

    await strategy.getToken();
    await strategy.getToken();

    expect(jwt.calls()).toBe(2);
  });

  it("surfaces a getJwt rejection as an error with .code", async () => {
    server.mockAuthorizeEndpoint();
    const strategy = OidcFederationStrategy.create(WORKSPACE_CRN, () =>
      Promise.reject(new Error("provider unavailable")),
    );

    try {
      await strategy.getToken();
      expect.unreachable("getToken should reject when getJwt rejects");
    } catch (err) {
      expect((err as AuthError).code).toBe("SERVER_ERROR");
    }
  });

  it("honours an explicit baseUrl override over CS_CTS_HOST", async () => {
    // CS_CTS_HOST (set in beforeEach) points at `server`, which here 500s on
    // federation. A second server is the override target and succeeds. If the
    // napi `baseUrl` arg is threaded through `maybe_base_url`, federation hits
    // the override and resolves; if the override were dropped, it would hit
    // CS_CTS_HOST's 500 and reject. This proves the precedence guarantee
    // motivating CIP-3246 survives the napi parameter threading — the Rust core
    // proves the ordering, this proves the binding preserves it.
    server.mockAuthorizeEndpointError();
    const override = await MockAuthServer.start();
    try {
      override.mockAuthorizeEndpoint();
      const strategy = OidcFederationStrategy.create(
        WORKSPACE_CRN,
        () => Promise.resolve("header.payload.signature"),
        override.baseUrl,
      );

      const result = await strategy.getToken();

      expect(result.workspaceId).toBe(WORKSPACE_ID);
    } finally {
      override.clearMocks();
    }
  });

  it("honours a baseUrl override over CS_CTS_HOST for createWithStore", async () => {
    // The store-variant twin of the precedence test: `baseUrl` is the 5th
    // positional arg here (vs the 3rd on `create`), threaded through a separate
    // wrapper path in index.js. CS_CTS_HOST's `server` 500s; the override
    // server succeeds. getToken resolving (and the token landing in the store)
    // proves the 5th-positional override is threaded, not dropped or
    // mis-positioned.
    server.mockAuthorizeEndpointError();
    const override = await MockAuthServer.start();
    try {
      override.mockAuthorizeEndpoint();
      const store = memStore();
      const strategy = OidcFederationStrategy.createWithStore(
        WORKSPACE_CRN,
        () => Promise.resolve("header.payload.signature"),
        store.load,
        store.save,
        override.baseUrl,
      );

      const result = await strategy.getToken();

      expect(result.workspaceId).toBe(WORKSPACE_ID);
      expect(store.saved()).not.toBeNull();
    } finally {
      override.clearMocks();
    }
  });

  it("rejects a malformed baseUrl with INVALID_URL", () => {
    // The napi twin of the wasm `..._rejects_invalid_base_url` test: a
    // non-empty, unparseable override must surface through the factory as a
    // coded INVALID_URL error (via `maybe_base_url(...)? → to_napi_error`), not
    // a silent fallback or an un-coded throw.
    try {
      OidcFederationStrategy.create(
        WORKSPACE_CRN,
        () => Promise.resolve("h.p.s"),
        "not a url",
      );
      expect.unreachable("create should throw on a malformed baseUrl");
    } catch (err) {
      expect((err as AuthError).code).toBe("INVALID_URL");
    }
  });

  it("treats an empty baseUrl as absent (falls back to CS_CTS_HOST)", async () => {
    // An empty-string override must be a no-op, not an INVALID_URL — so
    // federation still resolves against CS_CTS_HOST's mock.
    server.mockAuthorizeEndpoint();
    const strategy = OidcFederationStrategy.create(
      WORKSPACE_CRN,
      () => Promise.resolve("header.payload.signature"),
      "",
    );

    const result = await strategy.getToken();

    expect(result.workspaceId).toBe(WORKSPACE_ID);
  });

  it("rejects an invalid workspace CRN with .code", () => {
    try {
      OidcFederationStrategy.create("not-a-crn", () =>
        Promise.resolve("h.p.s"),
      );
      expect.unreachable("create should throw on a malformed workspace CRN");
    } catch (err) {
      expect((err as AuthError).code).toBe("INVALID_CRN");
    }
  });

  it("rejects a CRN whose workspace segment is malformed with .code", () => {
    // "not-a-crn" above fails at the `crn:` prefix; this is the distinct path
    // where the prefix/region parse but the workspace segment fails validation
    // — what the old INVALID_WORKSPACE_ID case covered before the CRN switch.
    try {
      OidcFederationStrategy.create(
        "crn:ap-southeast-2.aws:not-a-valid-workspace",
        () => Promise.resolve("h.p.s"),
      );
      expect.unreachable(
        "create should throw on a malformed workspace segment",
      );
    } catch (err) {
      expect((err as AuthError).code).toBe("INVALID_CRN");
    }
  });

  it("persists the federated token to the store", async () => {
    server.mockAuthorizeEndpoint();
    const store = memStore();
    const jwt = countingJwt();
    const strategy = OidcFederationStrategy.createWithStore(
      WORKSPACE_CRN,
      jwt.getJwt,
      store.load,
      store.save,
    );

    await strategy.getToken();

    expect(store.saved()).not.toBeNull();
    expect(jwt.calls()).toBe(1);
  });

  it("loads a cached token from the store without re-federating", async () => {
    // First strategy federates and populates the shared store.
    server.mockAuthorizeEndpoint();
    const store = memStore();
    const first = OidcFederationStrategy.createWithStore(
      WORKSPACE_CRN,
      () => Promise.resolve("h.p.s"),
      store.load,
      store.save,
    );
    await first.getToken();
    expect(store.saved()).not.toBeNull();

    // Second strategy shares the store. Federation would fail (500) and getJwt
    // would throw — proving the token came from the store, not the network.
    server.clearMocks();
    server.mockAuthorizeEndpointError();
    const second = OidcFederationStrategy.createWithStore(
      WORKSPACE_CRN,
      () => Promise.reject(new Error("getJwt must not be called")),
      store.load,
      store.save,
    );

    const result = await second.getToken();
    expect(result.workspaceId).toBe(WORKSPACE_ID);
  });

  it("re-federates when the stored token JSON is malformed", async () => {
    // A corrupt cookie/store value must be treated as a cache miss (the
    // `serde_json::from_str(..).ok()` → None branch), not panic — so federation
    // runs fresh. A version that `unwrap()`ed the parse would fail this.
    server.mockAuthorizeEndpoint();
    const jwt = countingJwt();
    const strategy = OidcFederationStrategy.createWithStore(
      WORKSPACE_CRN,
      jwt.getJwt,
      () => Promise.resolve("}{ not json"),
      (_json: string) => Promise.resolve(),
    );

    await strategy.getToken();

    // Garbage cache discarded → exactly one fresh federation.
    expect(jwt.calls()).toBe(1);
  });

  it("surfaces a non-string getJwt result as an error with .code", async () => {
    // Mirrors the wasm `js_oidc_provider_errors_on_non_string_result` test:
    // a `Promise<number>` fails napi's `Promise<String>` coercion and must
    // surface as a clean SERVER_ERROR rejection, not a panic or hung promise.
    server.mockAuthorizeEndpoint();
    const strategy = OidcFederationStrategy.create(WORKSPACE_CRN, () =>
      Promise.resolve(42 as unknown as string),
    );

    try {
      await strategy.getToken();
      expect.unreachable(
        "getToken should reject on a non-string getJwt result",
      );
    } catch (err) {
      expect((err as AuthError).code).toBe("SERVER_ERROR");
    }
  });

  it("surfaces a federation server error with .code", async () => {
    // Negative twin of the happy path: a real federation request reaching
    // /api/authorise and getting a 500 must reject with an enriched `.code`,
    // not resolve or throw an un-coded error.
    server.mockAuthorizeEndpointError();
    const strategy = OidcFederationStrategy.create(WORKSPACE_CRN, () =>
      Promise.resolve("header.payload.signature"),
    );

    try {
      await strategy.getToken();
      expect.unreachable("getToken should reject when /api/authorise 500s");
    } catch (err) {
      expect(err as AuthError).toHaveProperty("code");
    }
  });
});
