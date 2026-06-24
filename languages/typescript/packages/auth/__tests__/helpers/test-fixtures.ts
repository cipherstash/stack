// Test fixtures that replace the Rust `test-utils` helpers (`saveTestToken` and
// the JWT minting inside `MockAuthServer`). The stack-auth claim readers call
// `insecure_disable_signature_validation()`, so a JWT only needs a well-formed
// header + base64url payload — no real HMAC signing, hence zero crypto deps.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const WORKSPACE_ID = "ZVATKW3VHMFG27DY";

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

/**
 * Mint an unsigned-but-well-formed JWT (`<header>.<payload>.sig`). Mirrors the
 * claims of `mock_auth_server::test_jwt`; `claims` overrides/extends them (e.g.
 * to add a `services` claim). The signature segment is a literal placeholder —
 * only the header `alg` and the payload are ever read.
 */
export function mintJwt(claims: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url({ alg: "HS256", typ: "JWT" });
  const payload = base64url({
    iss: "https://cts.example.com/",
    sub: "CS|test-user",
    aud: "test-audience",
    iat: now,
    exp: now + 3600,
    workspace: WORKSPACE_ID,
    scope: "",
    ...claims,
  });
  return `${header}.${payload}.sig`;
}

/**
 * Write a CTS auth token into a profile directory — the JS replacement for the
 * Rust `saveTestToken` napi helper. Mirrors `ProfileStore::init_workspace` plus
 * `save_with_mode("auth.json", .., 0o600)`: creates `workspaces/<ws>/`, points
 * the `current_workspace` file at it (what `bind_client_device` reads to locate
 * the token), and writes the token JSON. The token carries `services.zerokms`
 * so device provisioning can reach the mock ZeroKMS endpoint.
 *
 * Pair with `process.env.CS_CONFIG_PATH = profileDir` so the production
 * `bindClientDevice()` resolves this directory.
 */
export function saveTestToken(
  profileDir: string,
  zerokmsBaseUrl: string,
): void {
  const now = Math.floor(Date.now() / 1000);
  const jwt = mintJwt({
    aud: "legacy-aud-value",
    services: { zerokms: zerokmsBaseUrl },
  });
  const tokenJson = {
    access_token: jwt,
    token_type: "Bearer",
    expires_at: now + 3600,
  };
  const wsDir = join(profileDir, "workspaces", WORKSPACE_ID);
  mkdirSync(wsDir, { recursive: true });
  writeFileSync(join(profileDir, "current_workspace"), WORKSPACE_ID);
  writeFileSync(join(wsDir, "auth.json"), JSON.stringify(tokenJson), {
    mode: 0o600,
  });
}
