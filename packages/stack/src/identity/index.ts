import { type Result, withResult } from '@byteslice/result'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import { loadWorkSpaceId } from '@/utils/config'
import { logger } from '@/utils/logger'

/**
 * How much of an error body to quote back. A refusal is one sentence; a
 * gateway failing in front of CTS can be a page of HTML, and that belongs in
 * nobody's `Error.message`.
 */
const MAX_BODY_CHARS = 300

const KNOWN_REFUSALS: ReadonlySet<string> = new Set([
  'USAGE_LIMIT_EXCEEDED',
  'ORG_NOT_PROVISIONED',
])

/**
 * Classify a `/api/authorize` refusal, mirroring `classify_issuance_failure` in
 * `stack-auth` (`src/error.rs`) so this seam and the Rust client cannot
 * disagree about what the same response means.
 *
 * This is the only place in the SDK that reads a CTS response itself, so it is
 * the only place that has to know the wire shape. Everywhere else the refusal
 * arrives through protect-ffi with `authCode`, `help` and `url` already
 * attached by `stack-auth`.
 *
 * A `402` carrying a usage refusal is JSON (`AuthorizeErrorBody` in
 * `cts-web/src/authorize/mod.rs`):
 *
 * ```json
 * {"error":"usage_limit_exceeded",
 *  "error_description":"Workspace has exceeded its usage limit and cannot issue an access token",
 *  "cs_code":"USAGE_LIMIT_EXCEEDED"}
 * ```
 *
 * The rules, in the order they are applied:
 *
 * - **Status decides, not the body.** Only a `402` is a usage refusal. The
 *   OAuth issuance paths must report one as `access_denied` to stay RFC 6749
 *   compliant, so the body alone cannot be trusted to say what it is.
 * - **An empty body reads as `USAGE_LIMIT_EXCEEDED`.** Deployments predating
 *   `cs_code` sent a bodyless `402`, and that only ever meant the usage limit.
 * - **A non-empty body must parse as a JSON object.** A `402` that is HTML, or
 *   valid JSON that is not an object, did not come from CTS — it came from a
 *   proxy, WAF or gateway in front of it. Declining sends the caller down the
 *   generic path; asserting a billing remedy over a gateway failure sends them
 *   to a billing page for something a retry would have cleared.
 * - **`cs_code` must name a known account refusal.** Unknown codes decline so
 *   a future use of `402` does not inherit today's billing classification.
 * - **`cs_code` absent defaults to `USAGE_LIMIT_EXCEEDED`.** This preserves
 *   compatibility with deployments predating the taxonomy field, including
 *   OAuth responses whose `error` remains `access_denied`.
 *
 * Note what this deliberately does NOT do: call `response.json()`. Only the
 * `402` is JSON. Every other failure from this endpoint is
 * `(StatusCode, self.to_string())` — a `401` is the bare string
 * `Authorization failed: InvalidToken` — and `.json()` on one throws a
 * `SyntaxError` that displaces the real failure. The body is read as text
 * exactly once and parsed defensively.
 */
function readCtsRefusal(
  status: number,
  raw: string,
): { authCode?: string; description?: string } {
  if (status !== 402) return {}

  const trimmed = raw.trim()
  if (!trimmed) return { authCode: 'USAGE_LIMIT_EXCEEDED' }

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    return {}
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return {}
  }

  const body = parsed as Record<string, unknown>
  const field = (name: string): string | undefined => {
    const value = body[name]
    return typeof value === 'string' && value.trim() !== ''
      ? value.trim()
      : undefined
  }

  const description = field('error_description')

  // Presence is decided on the raw value, not on a string projection of it: a
  // non-string `cs_code` must not read as absent and fall through to the
  // `error` arm, which is the inversion of what this guard is for.
  if ('cs_code' in body) {
    const code = field('cs_code')
    return code && KNOWN_REFUSALS.has(code)
      ? { authCode: code, description }
      : { description }
  }

  return { authCode: 'USAGE_LIMIT_EXCEEDED', description }
}

/**
 * Turn a non-2xx `/api/authorize` response into the failure a caller can act
 * on: the status, what CTS actually said, and — when CTS refused on billing
 * grounds — the code to branch on plus the remedy naming where to fix it.
 */
async function ctsRefusalFailure(response: Response): Promise<EncryptionError> {
  const raw = await response.text().catch(() => '')
  const { authCode, description } = readCtsRefusal(response.status, raw)

  // Prefer the service's own `error_description` over the whole envelope: on a
  // classified refusal it is the sentence a human wants, and quoting the raw
  // JSON around it adds nothing a caller cannot get from `authCode`.
  const body = (description ?? raw.trim()).slice(0, MAX_BODY_CHARS)

  const context = `The CipherStash API returned ${response.status} for the CTS token request`

  return {
    type: EncryptionErrorTypes.CtsTokenError,
    message: body ? `${context}: ${body}` : `${context}.`,
    ...(authCode ? { authCode } : {}),
  }
}

export type CtsRegions = 'ap-southeast-2'

export type IdentifyOptions = {
  fetchFromCts?: boolean
}

export type CtsToken = {
  accessToken: string
  expiry: number
}

export type Context = {
  identityClaim: string[]
}

export type LockContextOptions = {
  context?: Context
  ctsToken?: CtsToken
}

export type GetLockContextResponse = {
  ctsToken?: CtsToken
  context: Context
}

/**
 * The accepted argument to `.withLockContext()` — either a {@link LockContext}
 * or a plain identity-claim spec (e.g. `{ identityClaim: ['sub'] }`).
 */
export type LockContextInput = LockContext | Context

/**
 * Resolve a {@link LockContextInput} to the {@link Context} (identity claim)
 * that protect-ffi expects. Synchronous — no token round-trip.
 */
export function resolveLockContext(input: LockContextInput): Context {
  // Use a structural check as well as `instanceof` so a `LockContext`
  // constructed in another realm (or from a duplicate module instance) is still
  // resolved rather than slipping through as a raw `Context`.
  return input instanceof LockContext || 'identityContext' in input
    ? (input as LockContext).identityContext
    : input
}

/**
 * Binds an encryption/decryption operation to a user's identity by selecting
 * which JWT claim(s) ZeroKMS bakes into the data key's tag (the *lock context*).
 *
 * The claim **value** is resolved by ZeroKMS from the token that authenticates
 * the request — so to bind to a real end user, authenticate the client as that
 * user with an `OidcFederationStrategy` (from `@cipherstash/auth`) and pass the
 * claim to `.withLockContext()`. The same context must be supplied to decrypt.
 *
 * You can pass a plain `{ identityClaim }` directly — constructing a
 * `LockContext` is optional.
 *
 * @example
 * ```typescript
 * import { Encryption } from "@cipherstash/stack"
 * import { OidcFederationStrategy } from "@cipherstash/auth"
 *
 * // Authenticate the client as the end user (replaces the old identify() flow).
 * const client = await Encryption({
 *   schemas,
 *   config: {
 *     authStrategy: OidcFederationStrategy.create(workspaceCrn, () => getJwt()),
 *   },
 * })
 *
 * // Bind the key to the user's `sub` claim — no token, no identify().
 * const result = await client
 *   .encrypt(value, { column: users.email, table: users })
 *   .withLockContext({ identityClaim: ["sub"] })
 * ```
 */
export class LockContext {
  private ctsToken: CtsToken | undefined
  private workspaceId: string
  private context: Context

  constructor({
    context = { identityClaim: ['sub'] },
    ctsToken,
  }: LockContextOptions = {}) {
    const workspaceId = loadWorkSpaceId()

    if (!workspaceId) {
      throw new Error(
        'You have not defined a workspace ID in your config file, or the CS_WORKSPACE_CRN environment variable.',
      )
    }

    if (ctsToken) {
      this.ctsToken = ctsToken
    }

    this.workspaceId = workspaceId
    this.context = context
    logger.debug('Successfully initialized the EQL lock context.')
  }

  /**
   * The identity-claim context this lock context binds to, e.g.
   * `{ identityClaim: ['sub'] }`. Resolved synchronously — `.withLockContext()`
   * uses this directly; no CTS token is required.
   */
  get identityContext(): Context {
    return this.context
  }

  /**
   * Exchange a user's JWT for a CTS token and bind it to this lock context.
   *
   * @deprecated Per-operation CTS tokens were removed in protect-ffi 0.25.
   * Authenticate the client as the user with an `OidcFederationStrategy`
   * (`config.authStrategy`) instead, and pass the claim to `.withLockContext()`.
   * The token fetched here is no longer used by encryption operations. This
   * method is kept for backwards compatibility and will be removed in a
   * future major release.
   *
   * @param jwtToken - A valid OIDC / JWT token for the current user.
   * @returns A `Result` containing this `LockContext` or an error.
   */
  async identify(
    jwtToken: string,
  ): Promise<Result<LockContext, EncryptionError>> {
    const workspaceId = this.workspaceId

    const ctsEndpoint =
      process.env.CS_CTS_ENDPOINT ||
      'https://ap-southeast-2.aws.auth.viturhosted.net'

    const ctsFetchResult = await withResult(
      () =>
        fetch(`${ctsEndpoint}/api/authorize`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            workspaceId,
            oidcToken: jwtToken,
          }),
        }),
      (error) => ({
        type: EncryptionErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )

    if (ctsFetchResult.failure) {
      return ctsFetchResult
    }

    // `fetch` only rejects on a transport failure, so the block above sees a
    // network error and nothing else: a CTS `402` carrying
    // `cs_code: USAGE_LIMIT_EXCEEDED` RESOLVES, and without this check the body would
    // fall through to the token parse below and be reported as a malformed
    // response ("did not contain an access token. Please contact support.") —
    // a support ticket for a billing state, or a JSON syntax error for a
    // plain-text one. This is the only place in the SDK that talks to CTS
    // directly; everywhere else the refusal arrives through protect-ffi with
    // `authCode` already attached.
    if (!ctsFetchResult.data.ok) {
      return { failure: await ctsRefusalFailure(ctsFetchResult.data) }
    }

    const identifiedLockContext = await withResult(
      async () => {
        const ctsToken = (await ctsFetchResult.data.json()) as CtsToken

        if (!ctsToken.accessToken) {
          throw new Error(
            'The response from the CipherStash API did not contain an access token. Please contact support.',
          )
        }

        this.ctsToken = ctsToken
        return this
      },
      (error) => ({
        type: EncryptionErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )

    return identifiedLockContext
  }

  /**
   * Retrieve the identity context (and CTS token, if one was set).
   *
   * @deprecated Encryption operations no longer consume a CTS token — they read
   * the identity claim directly via {@link identityContext}. Pass the claim to
   * `.withLockContext()` and authenticate the client with an
   * `OidcFederationStrategy` instead. Kept for backwards compatibility; the
   * returned `ctsToken` is `undefined` unless one was supplied to the
   * constructor or {@link identify} was called.
   */
  getLockContext(): Promise<Result<GetLockContextResponse, EncryptionError>> {
    return withResult(
      () => ({
        context: this.context,
        // Only include `ctsToken` when one was actually set, so the
        // returned shape matches the optional `ctsToken?` type rather
        // than carrying an explicit `undefined`.
        ...(this.ctsToken ? { ctsToken: this.ctsToken } : {}),
      }),
      (error) => ({
        type: EncryptionErrorTypes.CtsTokenError,
        message: error.message,
      }),
    )
  }
}
