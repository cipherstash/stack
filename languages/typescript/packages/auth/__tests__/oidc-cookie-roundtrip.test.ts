import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { MockAuthServer as MockAuthServerType } from "../test-utils";
import { cookieStore } from "../cookies.mjs";

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

/** Extract the `name=value` pair from a `Set-Cookie` header. */
function cookiePair(setCookie: string): string {
  return setCookie.split(";")[0];
}

/** A `Request` carrying the given `Cookie:` header (or none). */
function requestWith(cookie?: string): Request {
  return new Request("https://example.com/", {
    headers: cookie ? { cookie } : {},
  });
}

describe("OidcFederationStrategy + cookieStore round-trip", () => {
  it("writes the federated CTS token to a Set-Cookie header", async () => {
    server.mockAuthorizeEndpoint();
    const responseHeaders = new Headers();
    const store = cookieStore({ request: requestWith(), responseHeaders });

    const strategy = OidcFederationStrategy.createWithStore(
      REGION,
      WORKSPACE_ID,
      () => Promise.resolve("header.payload.signature"),
      store.load,
      store.save,
    );
    const result = await strategy.getToken();

    expect(result.workspaceId).toBe(WORKSPACE_ID);
    const setCookie = responseHeaders.get("set-cookie");
    expect(setCookie).toBeTruthy();
    expect(setCookie).toMatch(/^cs_token=/);
  });

  it("reuses a cached token from the cookie without re-federating", async () => {
    // First request federates and writes the cookie.
    server.mockAuthorizeEndpoint();
    const firstHeaders = new Headers();
    const firstStore = cookieStore({
      request: requestWith(),
      responseHeaders: firstHeaders,
    });
    const first = OidcFederationStrategy.createWithStore(
      REGION,
      WORKSPACE_ID,
      () => Promise.resolve("header.payload.signature"),
      firstStore.load,
      firstStore.save,
    );
    await first.getToken();
    const cookie = cookiePair(firstHeaders.get("set-cookie")!);

    // Second request carries the cookie. Federation would fail (500) and
    // getJwt would throw — proving the token came from the cookie.
    server.clearMocks();
    server.mockAuthorizeEndpointError();
    const secondStore = cookieStore({
      request: requestWith(cookie),
      responseHeaders: new Headers(),
    });
    const second = OidcFederationStrategy.createWithStore(
      REGION,
      WORKSPACE_ID,
      () => Promise.reject(new Error("getJwt must not be called")),
      secondStore.load,
      secondStore.save,
    );

    const result = await second.getToken();
    expect(result.workspaceId).toBe(WORKSPACE_ID);
  });

  it("re-federates when the cookie holds an expired token", async () => {
    // First request federates a token that is immediately expired (expiry 0).
    server.mockAuthorizeEndpoint(0);
    const firstHeaders = new Headers();
    const firstStore = cookieStore({
      request: requestWith(),
      responseHeaders: firstHeaders,
    });
    const first = OidcFederationStrategy.createWithStore(
      REGION,
      WORKSPACE_ID,
      () => Promise.resolve("header.payload.signature"),
      firstStore.load,
      firstStore.save,
    );
    await first.getToken();
    const cookie = cookiePair(firstHeaders.get("set-cookie")!);

    // Second request carries the expired cookie. getToken() must re-federate
    // — calling getJwt again — rather than serving the stale token.
    server.clearMocks();
    server.mockAuthorizeEndpoint();
    let getJwtCalls = 0;
    const secondStore = cookieStore({
      request: requestWith(cookie),
      responseHeaders: new Headers(),
    });
    const second = OidcFederationStrategy.createWithStore(
      REGION,
      WORKSPACE_ID,
      () => {
        getJwtCalls += 1;
        return Promise.resolve("header.payload.signature");
      },
      secondStore.load,
      secondStore.save,
    );

    const result = await second.getToken();
    expect(result.workspaceId).toBe(WORKSPACE_ID);
    expect(getJwtCalls).toBe(1);
  });
});
