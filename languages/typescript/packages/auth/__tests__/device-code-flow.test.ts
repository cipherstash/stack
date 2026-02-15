import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { MockAuthServer as MockAuthServerType } from "../test-utils";
import type {
  DeviceCodeResult,
  TokenResult,
  AuthError,
} from "../index";

// Load the CJS module — includes MockAuthServer when built with test-utils.
const mod = require("../index.js") as typeof import("../index") & {
  MockAuthServer: typeof MockAuthServerType;
};

const {
  beginDeviceCodeFlow,
  beginDeviceCodeFlowWithBaseUrl,
  MockAuthServer,
} = mod;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let server: InstanceType<typeof MockAuthServerType>;

async function startServer(): Promise<InstanceType<typeof MockAuthServerType>> {
  const s = await MockAuthServer.start();
  s.mockDeviceCodeEndpoint();
  return s;
}

async function beginFlow(): Promise<DeviceCodeResult> {
  return beginDeviceCodeFlowWithBaseUrl(
    "ap-southeast-2.aws",
    "test-client",
    server.baseUrl,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("device code flow (TypeScript / vitest)", () => {
  // ---------- Error enrichment (no server needed) ----------

  it("attaches .code for INVALID_REGION", async () => {
    try {
      await beginDeviceCodeFlow("not-a-region", "test-client");
      expect.unreachable("should have thrown");
    } catch (err) {
      const authErr = err as AuthError;
      expect(authErr).toBeInstanceOf(Error);
      expect(authErr.code).toBe("INVALID_REGION");
    }
  });

  it("beginDeviceCodeFlowWithBaseUrl rejects for invalid region", async () => {
    try {
      await beginDeviceCodeFlowWithBaseUrl(
        "not-a-region",
        "test-client",
        "http://localhost:9999",
      );
      expect.unreachable("should have thrown");
    } catch (err) {
      const authErr = err as AuthError;
      expect(authErr).toBeInstanceOf(Error);
      expect(authErr.code).toBe("INVALID_REGION");
    }
  });

  // ---------- Tests that need the mock server ----------

  describe("with mock server", () => {
    beforeEach(async () => {
      server = await startServer();
    });

    it("exposes getter fields on DeviceCodeResult", async () => {
      const result = await beginFlow();

      expect(result.userCode).toBe("ABCD-EFGH");
      expect(result.verificationUri).toBe("http://example.com/activate");
      expect(result.verificationUriComplete).toBe(
        "http://example.com/activate?user_code=ABCD-EFGH",
      );
      expect(result.expiresIn).toBe(900);
    });

    it("pollForToken resolves with token on success", async () => {
      server.mockTokenEndpoint();
      const result = await beginFlow();
      const token: TokenResult = await result.pollForToken();

      expect(token.accessToken).toBe("test_access_token_value");
      expect(token.tokenType).toBe("Bearer");
      expect(token.expiresIn).toBe(3600);
    });

    it("pollForToken rejects on second call (consumed handle)", async () => {
      server.mockTokenEndpoint();
      const result = await beginFlow();

      // First call succeeds — consumes the handle
      await result.pollForToken();

      // Second call should fail
      try {
        await result.pollForToken();
        expect.unreachable("should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(Error);
        expect((err as Error).message).toMatch(/already been consumed/);
      }
    });

    it("pollForToken rejects with enriched ACCESS_DENIED", async () => {
      server.mockTokenEndpointError("access_denied");
      const result = await beginFlow();

      try {
        await result.pollForToken();
        expect.unreachable("should have thrown");
      } catch (err) {
        const authErr = err as AuthError;
        expect(authErr).toBeInstanceOf(Error);
        expect(authErr.code).toBe("ACCESS_DENIED");
      }
    });

    it("pollForToken rejects with enriched EXPIRED_TOKEN", async () => {
      server.mockTokenEndpointError("expired_token");
      const result = await beginFlow();

      try {
        await result.pollForToken();
        expect.unreachable("should have thrown");
      } catch (err) {
        const authErr = err as AuthError;
        expect(authErr).toBeInstanceOf(Error);
        expect(authErr.code).toBe("EXPIRED_TOKEN");
      }
    });
  });
});
