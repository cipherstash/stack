import { describe, it, expect, beforeEach, afterEach } from "vitest";
import type { DeviceCodeResult } from "../index";
import { MockCtsServer } from "./helpers/mock-cts-server";

const { beginDeviceCodeFlow } =
  require("../index.js") as typeof import("../index");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let server: MockCtsServer;

async function startServer(): Promise<MockCtsServer> {
  const s = await MockCtsServer.start();
  s.mockDeviceCodeEndpoint();
  return s;
}

// The production `beginDeviceCodeFlow` resolves its auth host from CS_CTS_HOST
// (set in `beforeEach` below), so no test-only base-URL override is needed.
async function beginFlow(): Promise<DeviceCodeResult> {
  const r = await beginDeviceCodeFlow("ap-southeast-2.aws", "test-client");
  if (r.failure) {
    expect.unreachable(`beginDeviceCodeFlow failed: ${r.failure.type}`);
  }
  return r.data;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("device code flow (TypeScript / vitest)", () => {
  // ---------- Error enrichment (no server needed) ----------

  it("attaches .type for INVALID_REGION", async () => {
    const r = await beginDeviceCodeFlow("not-a-region", "test-client");
    expect(r.failure?.error).toBeInstanceOf(Error);
    expect(r.failure?.type).toBe("INVALID_REGION");
  });

  // ---------- Tests that need the mock server ----------

  describe("with mock server", () => {
    let savedHost: string | undefined;

    beforeEach(async () => {
      server = await startServer();
      savedHost = process.env.CS_CTS_HOST;
      process.env.CS_CTS_HOST = server.baseUrl;
    });

    afterEach(async () => {
      if (savedHost === undefined) {
        delete process.env.CS_CTS_HOST;
      } else {
        process.env.CS_CTS_HOST = savedHost;
      }
      await server.close();
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

    it("pollForToken resolves with auth metadata on success", async () => {
      server.mockTokenEndpoint();
      const result = await beginFlow();
      const pr = await result.pollForToken();
      if (pr.failure) {
        expect.unreachable(`pollForToken failed: ${pr.failure.type}`);
      }
      const auth = pr.data;

      expect(auth.expiresAt).toBeGreaterThan(0);
      expect(auth.expiresIn).toBeGreaterThanOrEqual(3598);
      expect(auth.expiresIn).toBeLessThanOrEqual(3600);
    });

    it("pollForToken fails on second call (consumed handle)", async () => {
      server.mockTokenEndpoint();
      const result = await beginFlow();

      // First call succeeds — consumes the handle
      const first = await result.pollForToken();
      if (first.failure) {
        expect.unreachable(`first pollForToken failed: ${first.failure.type}`);
      }

      // Second call should surface a failure
      const second = await result.pollForToken();
      expect(second.failure?.error).toBeInstanceOf(Error);
      expect(second.failure?.type).toBe("ALREADY_CONSUMED");
      expect(second.failure?.error.message).toMatch(/already consumed/i);
    });

    it("pollForToken fails with enriched ACCESS_DENIED", async () => {
      server.mockTokenEndpointError("access_denied");
      const result = await beginFlow();

      const pr = await result.pollForToken();
      expect(pr.failure?.error).toBeInstanceOf(Error);
      expect(pr.failure?.type).toBe("ACCESS_DENIED");
    });

    it("pollForToken fails with enriched EXPIRED_TOKEN", async () => {
      server.mockTokenEndpointError("expired_token");
      const result = await beginFlow();

      const pr = await result.pollForToken();
      expect(pr.failure?.error).toBeInstanceOf(Error);
      expect(pr.failure?.type).toBe("EXPIRED_TOKEN");
    });
  });
});
