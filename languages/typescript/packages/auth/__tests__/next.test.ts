import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  csFederate,
  csFederationMiddleware,
  csAuthHeader,
  csTokenCookieName,
  encodeTokenHeader,
  decodeTokenHeader,
  CS_TOKEN_HEADER,
} from "../next.mjs";

// Mock the wasm strategy so these tests exercise the adapter's OWN wiring
// (cookie persistence, header encode/decode, warmed-token reads) deterministically
// and offline. The real federate-or-reuse + cookie round-trip against a CTS
// server is covered by `oidc-cookie-roundtrip.test.ts`. `vi.hoisted` lets the
// hoisted `vi.mock` factory reference these fns without a top-level await.
const { getToken, free, create } = vi.hoisted(() => ({
  getToken: vi.fn(),
  free: vi.fn(),
  create: vi.fn(),
}));

vi.mock("../wasm-inline.mjs", () => ({
  OidcFederationStrategy: {
    create: (
      crn: string,
      getJwt: () => unknown,
      options: { store?: { load(): unknown; save(json: string): unknown } },
    ) => create(crn, getJwt, options),
  },
}));

const WORKSPACE_ID = "ZVATKW3VHMFG27DY";
const WORKSPACE_CRN = `crn:ap-southeast-2.aws:${WORKSPACE_ID}`;

function tokenResult(overrides: Record<string, unknown> = {}) {
  return {
    token: "header.payload.signature",
    subject: `CS|${WORKSPACE_ID}`,
    workspaceId: WORKSPACE_ID,
    issuer: "https://cts.example.com",
    services: { zerokms: "https://zerokms.example.com" },
    ...overrides,
  };
}

function requestWith(cookie?: string): Request {
  return new Request("https://example.com/", {
    headers: cookie ? { cookie } : {},
  });
}

beforeEach(() => {
  getToken.mockReset();
  free.mockReset();
  create.mockReset();
  // Default fake strategy: writes the token to the store (so cookie wiring is
  // exercised) and returns a TokenResult.
  create.mockImplementation(
    (
      _crn: string,
      _getJwt: () => unknown,
      options: { store?: { save(json: string): unknown } },
    ) => {
      getToken.mockImplementation(async () => {
        await options.store?.save(
          JSON.stringify({
            access_token: "header.payload.signature",
            expires_at: Math.floor(Date.now() / 1000) + 3600,
          }),
        );
        return tokenResult();
      });
      return { getToken, free };
    },
  );
});

describe("csTokenCookieName", () => {
  it("is per-workspace", () => {
    expect(csTokenCookieName(WORKSPACE_ID)).toBe(`cs_token_${WORKSPACE_ID}`);
  });
});

describe("encode/decodeTokenHeader", () => {
  it("round-trips a TokenResult through the opaque header payload", () => {
    const r = tokenResult();
    const decoded = decodeTokenHeader(encodeTokenHeader(r));
    expect(decoded).toEqual(r);
  });

  it("produces a header-safe value (no base64 +/=/ chars)", () => {
    const v = encodeTokenHeader(tokenResult());
    expect(v).not.toMatch(/[+/=]/);
  });
});

describe("csFederate", () => {
  it("builds the strategy with the cookie-backed store and persists the token", async () => {
    const responseHeaders = new Headers();
    const result = await csFederate({
      request: requestWith(),
      responseHeaders,
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => "jwt",
      baseUrl: "https://cts.example.com",
      cookieName: csTokenCookieName(WORKSPACE_ID),
    });

    expect(result.workspaceId).toBe(WORKSPACE_ID);
    // baseUrl threaded through to the strategy.
    expect(create).toHaveBeenCalledWith(WORKSPACE_CRN, expect.any(Function), {
      store: expect.anything(),
      baseUrl: "https://cts.example.com",
    });
    // The cookie was written under the per-workspace name.
    const setCookie = responseHeaders.get("set-cookie");
    expect(setCookie).toMatch(new RegExp(`^cs_token_${WORKSPACE_ID}=`));
    // wasm resources released.
    expect(free).toHaveBeenCalledOnce();
  });
});

describe("csFederationMiddleware", () => {
  it("returns the warmed token header alongside the result", async () => {
    const responseHeaders = new Headers();
    const { result, headerName, headerValue } = await csFederationMiddleware({
      request: requestWith(),
      responseHeaders,
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => "jwt",
      cookieName: csTokenCookieName(WORKSPACE_ID),
    });

    expect(headerName).toBe(CS_TOKEN_HEADER);
    expect(decodeTokenHeader(headerValue)).toEqual(result);
    // Both caches populated: cookie (cross-request) + header (same-request).
    expect(responseHeaders.get("set-cookie")).toBeTruthy();
  });

  it("honours a custom header name", async () => {
    const { headerName } = await csFederationMiddleware({
      request: requestWith(),
      responseHeaders: new Headers(),
      workspaceCrn: WORKSPACE_CRN,
      getJwt: () => "jwt",
      cookieName: csTokenCookieName(WORKSPACE_ID),
      headerName: "x-warm",
    });
    expect(headerName).toBe("x-warm");
  });
});

describe("csAuthHeader", () => {
  it("reads a warmed token from the request header into a no-federation strategy", async () => {
    const headers = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader(tokenResult()),
    });
    const strategy = csAuthHeader(headers);
    expect(strategy).not.toBeNull();
    expect(strategy?.requiresFederation).toBe(false);
    expect((await strategy?.getToken())?.workspaceId).toBe(WORKSPACE_ID);
  });

  it("reads eagerly at construction (later header mutation is ignored)", async () => {
    const headers = new Headers({
      [CS_TOKEN_HEADER]: encodeTokenHeader(tokenResult({ token: "first" })),
    });
    const strategy = csAuthHeader(headers);
    headers.set(
      CS_TOKEN_HEADER,
      encodeTokenHeader(tokenResult({ token: "second" })),
    );
    expect((await strategy?.getToken())?.token).toBe("first");
  });

  it("returns null when no warmed token is present (cold fallback)", () => {
    expect(csAuthHeader(new Headers())).toBeNull();
  });

  it("returns null on a malformed header rather than throwing", () => {
    const headers = new Headers({ [CS_TOKEN_HEADER]: "not-valid-base64url!!" });
    expect(csAuthHeader(headers)).toBeNull();
  });

  it("honours a custom header name", async () => {
    const headers = new Headers({ "x-warm": encodeTokenHeader(tokenResult()) });
    expect(csAuthHeader(headers, { headerName: "x-warm" })).not.toBeNull();
    expect(csAuthHeader(headers)).toBeNull();
  });
});
