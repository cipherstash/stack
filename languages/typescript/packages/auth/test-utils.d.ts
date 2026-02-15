/**
 * Type declarations for `@cipherstash/stack-auth` test utilities.
 *
 * These exports are only available when the native module is built with the
 * `test-utils` Cargo feature (`napi build --features test-utils`).
 */

/**
 * A mock OAuth auth server for integration tests.
 *
 * Wraps an HTTP server that can be configured with canned responses for
 * the device-code and token endpoints.
 *
 * @example
 * ```ts
 * const server = await MockAuthServer.start();
 * server.mockDeviceCodeEndpoint();
 * server.mockTokenEndpoint();
 *
 * const result = await beginDeviceCodeFlowWithBaseUrl(
 *   "ap-southeast-2.aws",
 *   "test-client",
 *   server.baseUrl,
 * );
 * const token = await result.pollForToken();
 * ```
 */
export class MockAuthServer {
  /** Start a mock auth server on a random port. */
  static start(): Promise<MockAuthServer>;

  /** The base URL of the running mock server (e.g. `http://127.0.0.1:12345`). */
  readonly baseUrl: string;

  /**
   * Register a mock for `POST /oauth/device/code` that returns a standard
   * device-code JSON response.
   */
  mockDeviceCodeEndpoint(): void;

  /**
   * Register a mock for `POST /oauth/device/token` that returns a standard
   * token JSON response.
   */
  mockTokenEndpoint(): void;

  /**
   * Register a mock for `POST /oauth/device/token` that returns a 400 error
   * with the given OAuth error code and optional description.
   *
   * @param code - OAuth error code (e.g. `"access_denied"`, `"expired_token"`).
   * @param description - Optional human-readable description. Defaults to `"<code> occurred"`.
   */
  mockTokenEndpointError(code: string, description?: string): void;

  /** Remove all registered mocks. */
  clearMocks(): void;
}
