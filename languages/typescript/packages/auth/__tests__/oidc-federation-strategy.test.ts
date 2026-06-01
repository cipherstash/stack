import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { MockAuthServer as MockAuthServerType } from "../test-utils";
import type { AuthError } from "../index";

// Load the CJS module — includes MockAuthServer when built with test-utils.
const mod = require("../index.js") as typeof import("../index") & {
  MockAuthServer: typeof MockAuthServerType;
};

const { OidcFederationStrategy, MockAuthServer } = mod;

const REGION = "ap-southeast-2.aws";
const WORKSPACE_ID = "ZVATKW3VHMFG27DY";

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
    const strategy = OidcFederationStrategy.create(
      REGION,
      WORKSPACE_ID,
      jwt.getJwt,
    );

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
    const strategy = OidcFederationStrategy.create(
      REGION,
      WORKSPACE_ID,
      jwt.getJwt,
    );

    await strategy.getToken();
    await strategy.getToken();

    expect(jwt.calls()).toBe(2);
  });

  it("surfaces a getJwt rejection as an error with .code", async () => {
    server.mockAuthorizeEndpoint();
    const strategy = OidcFederationStrategy.create(REGION, WORKSPACE_ID, () =>
      Promise.reject(new Error("provider unavailable")),
    );

    try {
      await strategy.getToken();
      expect.unreachable("getToken should reject when getJwt rejects");
    } catch (err) {
      expect((err as AuthError).code).toBe("SERVER_ERROR");
    }
  });

  it("rejects an invalid workspace id with .code", () => {
    try {
      OidcFederationStrategy.create(REGION, "not-a-workspace-id", () =>
        Promise.resolve("h.p.s"),
      );
      expect.unreachable("create should throw on a malformed workspace id");
    } catch (err) {
      expect((err as AuthError).code).toBe("INVALID_WORKSPACE_ID");
    }
  });

  it("rejects an invalid region with .code", () => {
    try {
      OidcFederationStrategy.create("not-a-region", WORKSPACE_ID, () =>
        Promise.resolve("h.p.s"),
      );
      expect.unreachable("create should throw on a malformed region");
    } catch (err) {
      expect((err as AuthError).code).toBe("INVALID_REGION");
    }
  });

  it("persists the federated token to the store", async () => {
    server.mockAuthorizeEndpoint();
    const store = memStore();
    const jwt = countingJwt();
    const strategy = OidcFederationStrategy.createWithStore(
      REGION,
      WORKSPACE_ID,
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
      REGION,
      WORKSPACE_ID,
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
      REGION,
      WORKSPACE_ID,
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
      REGION,
      WORKSPACE_ID,
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
    const strategy = OidcFederationStrategy.create(REGION, WORKSPACE_ID, () =>
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
    const strategy = OidcFederationStrategy.create(REGION, WORKSPACE_ID, () =>
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
