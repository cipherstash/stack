// A zero-dependency mock CTS / auth server for the vitest suite, replacing the
// Rust `MockAuthServer` (which required the `test-utils` Cargo feature and
// pulled `mocktail`/`reqwest`/`jsonwebtoken` into the native module). Tests
// point the bindings at it via `CS_CTS_HOST` — the production strategies all
// resolve their host as `override → CS_CTS_HOST → discovery`, so no test-only
// Rust seam is needed.
//
// Each `mock*` method registers a one-shot-ish handler for a route; the server
// keeps the last handler registered per route. `clearMocks()` drops them all.

import { type Server, createServer } from "node:http";
import { mintJwt, WORKSPACE_ID } from "./test-fixtures";

type Handler = (body: string) => { status: number; json: unknown };

export class MockCtsServer {
  #server: Server;
  #routes = new Map<string, Handler>();
  #baseUrl = "";

  private constructor(server: Server) {
    this.#server = server;
  }

  /** Start a mock server on an ephemeral port and resolve once it's listening. */
  static async start(): Promise<MockCtsServer> {
    const mock = new MockCtsServer(
      createServer((req, res) => {
        const handler = mock.#routes.get(`${req.method} ${req.url}`);
        if (!handler) {
          res.writeHead(404, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "no mock registered" }));
          return;
        }
        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
        });
        req.on("end", () => {
          const { status, json } = handler(body);
          res.writeHead(status, { "content-type": "application/json" });
          res.end(JSON.stringify(json));
        });
      }),
    );

    await new Promise<void>((resolve) => {
      mock.#server.listen(0, "127.0.0.1", resolve);
    });
    const addr = mock.#server.address();
    if (addr === null || typeof addr === "string") {
      throw new Error("mock server did not bind a TCP port");
    }
    mock.#baseUrl = `http://127.0.0.1:${addr.port}`;
    return mock;
  }

  /** The base URL of the running mock server (e.g. `http://127.0.0.1:12345`). */
  get baseUrl(): string {
    return this.#baseUrl;
  }

  /** Stop the server and free its port. Call from `afterEach`. */
  async close(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.#server.close((err) => (err ? reject(err) : resolve()));
    });
  }

  #on(method: string, path: string, handler: Handler): void {
    this.#routes.set(`${method} ${path}`, handler);
  }

  // --- Device-code flow ---

  mockDeviceCodeEndpoint(): void {
    this.#on("POST", "/oauth/device/code", () => ({
      status: 200,
      json: {
        device_code: "test_device_code",
        user_code: "ABCD-EFGH",
        verification_uri: "http://example.com/activate",
        verification_uri_complete:
          "http://example.com/activate?user_code=ABCD-EFGH",
        expires_in: 900,
      },
    }));
  }

  mockTokenEndpoint(): void {
    this.#on("POST", "/oauth/device/token", () => ({
      status: 200,
      json: {
        access_token: mintJwt(),
        token_type: "Bearer",
        expires_in: 3600,
      },
    }));
  }

  mockTokenEndpointError(code: string, description?: string): void {
    this.#on("POST", "/oauth/device/token", () => ({
      status: 400,
      json: {
        error: code,
        error_description: description ?? `${code} occurred`,
      },
    }));
  }

  // --- OIDC federation ---

  /**
   * `expiry` is seconds-until-expiry; CTS returns the JWT `exp` as an ABSOLUTE
   * Unix epoch (CIP-3233), so convert to `now + expiry` — otherwise a freshly
   * federated token reads as already expired. Default 3600.
   */
  mockAuthorizeEndpoint(expiry = 3600): void {
    this.#on("POST", "/api/authorise", () => ({
      status: 200,
      json: {
        accessToken: mintJwt(),
        expiry: Math.floor(Date.now() / 1000) + expiry,
      },
    }));
  }

  mockAuthorizeEndpointError(): void {
    this.#on("POST", "/api/authorise", () => ({
      status: 500,
      json: { error: "federation failed" },
    }));
  }

  // --- ZeroKMS create-client (device provisioning) ---

  mockCreateClientEndpoint(): void {
    this.#on("POST", "/create-client", () => ({
      status: 200,
      json: {
        id: "00000000-0000-0000-0000-000000000001",
        dataset_id: "00000000-0000-0000-0000-000000000099",
        name: "test-device",
        description: "test-device",
        client_key: "dGVzdC1rZXktbWF0ZXJpYWw=",
      },
    }));
  }

  mockCreateClientConflict(): void {
    this.#on("POST", "/create-client", () => ({
      status: 409,
      json: { error: "conflict" },
    }));
  }

  clearMocks(): void {
    this.#routes.clear();
  }
}

export { WORKSPACE_ID };
