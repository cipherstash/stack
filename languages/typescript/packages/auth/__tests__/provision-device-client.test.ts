import { describe, it, expect, beforeEach } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import type { MockAuthServer as MockAuthServerType } from "../test-utils";
import type { AuthError } from "../index";

const mod = require("../index.js") as typeof import("../index") & {
  MockAuthServer: typeof MockAuthServerType;
  bindClientDeviceWithProfileDir: (profileDir: string) => Promise<void>;
  saveTestToken: (profileDir: string, zerokmsBaseUrl: string) => void;
};

const { MockAuthServer, bindClientDeviceWithProfileDir, saveTestToken } = mod;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_WORKSPACE_ID = "ZVATKW3VHMFG27DY";

let server: InstanceType<typeof MockAuthServerType>;
let profileDir: string;

async function startServer(): Promise<InstanceType<typeof MockAuthServerType>> {
  const s = await MockAuthServer.start();
  return s;
}

function freshProfileDir(): string {
  return mkdtempSync(join(tmpdir(), "cs-auth-test-"));
}

function workspaceDir(): string {
  return join(profileDir, "workspaces", TEST_WORKSPACE_ID);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("provision device client (TypeScript / vitest)", () => {
  beforeEach(async () => {
    server = await startServer();
    profileDir = freshProfileDir();
  });

  it("creates secretkey.json on successful provisioning", async () => {
    server.mockCreateClientEndpoint();
    saveTestToken(profileDir, server.baseUrl);

    await bindClientDeviceWithProfileDir(profileDir);

    const raw = readFileSync(join(workspaceDir(), "secretkey.json"), "utf-8");
    const secretKey = JSON.parse(raw);
    expect(secretKey.client_id).toBe("00000000-0000-0000-0000-000000000001");
    expect(secretKey.client_key).toBe("dGVzdC1rZXktbWF0ZXJpYWw=");
  });

  it("is a no-op when secretkey.json already exists", async () => {
    // No mock endpoints needed — should short-circuit before any HTTP call.
    saveTestToken(profileDir, server.baseUrl);

    // Pre-create secretkey.json in the workspace directory
    const existing = JSON.stringify({
      client_id: "existing-id",
      client_key: "existing-key",
    });
    writeFileSync(join(workspaceDir(), "secretkey.json"), existing);

    await bindClientDeviceWithProfileDir(profileDir);

    const raw = readFileSync(join(workspaceDir(), "secretkey.json"), "utf-8");
    const secretKey = JSON.parse(raw);
    expect(secretKey.client_id).toBe("existing-id");
  });

  it("is a no-op on 409 conflict", async () => {
    server.mockCreateClientConflict();
    saveTestToken(profileDir, server.baseUrl);

    await bindClientDeviceWithProfileDir(profileDir);

    expect(existsSync(join(workspaceDir(), "secretkey.json"))).toBe(false);
  });

  it("throws on server error", async () => {
    // No mock endpoint — server will return an error for unmatched route.
    saveTestToken(profileDir, server.baseUrl);

    try {
      await bindClientDeviceWithProfileDir(profileDir);
      expect.unreachable("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(Error);
    }
  });

  it("throws STORE_ERROR when auth token is missing", async () => {
    // No token saved — should fail trying to load auth.json
    try {
      await bindClientDeviceWithProfileDir(profileDir);
      expect.unreachable("should have thrown");
    } catch (err) {
      const authErr = err as AuthError;
      expect(authErr).toBeInstanceOf(Error);
      expect(authErr.code).toBe("STORE_ERROR");
    }
  });
});
