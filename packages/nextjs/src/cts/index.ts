import { NextResponse } from 'next/server'
import { logger } from '../../../utils/logger'
import {
  CS_COOKIE_NAME,
  type CtsToken,
  type GetCtsTokenResponse,
} from '../index'

/**
 * How much of an error body to quote back. A refusal is one sentence; a gateway
 * failing in front of CTS can be a page of HTML, and that belongs in nobody's
 * error string.
 */
const MAX_BODY_CHARS = 300

const KNOWN_REFUSALS: ReadonlySet<string> = new Set([
  'USAGE_LIMIT_EXCEEDED',
  'ORG_NOT_PROVISIONED',
])

/**
 * Classify a `/api/authorize` refusal, mirroring `classify_issuance_failure` in
 * CipherStash's `stack-auth` crate so this package and the Rust client cannot
 * disagree about what the same response means.
 *
 * A `402` carrying a usage refusal is JSON:
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
 *   proxy, WAF or gateway in front of it, and reporting that as a billing
 *   refusal sends the caller to a billing page for something a retry clears.
 * - **`cs_code` must name a known account refusal.** Unknown codes decline so
 *   a future use of `402` does not inherit today's classification.
 * - **`cs_code` absent defaults to `USAGE_LIMIT_EXCEEDED`.** This preserves
 *   compatibility with deployments predating the taxonomy field, including
 *   OAuth responses whose `error` remains `access_denied`.
 *
 * Note what this deliberately does NOT do: call `response.json()`. Only the
 * `402` is JSON. Every other failure from this endpoint is plain text — a `401`
 * is the bare string `Authorization failed: InvalidToken` — and `.json()` on
 * one throws a `SyntaxError` that displaces the real failure. The body is read
 * as text exactly once and parsed defensively.
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
 * Turn a non-2xx `/api/authorize` response into a failure a caller can act on:
 * the status, what CTS actually said, and — when CTS refused for a reason with a
 * code — that code.
 *
 * `statusText` is deliberately not reported. It is the empty string over
 * HTTP/2, which is what CTS speaks, so the message this used to produce was
 * `Failed to fetch CTS token: ` and nothing else — no status, no reason, no
 * code.
 *
 * No remedy text is attached here. The authoritative guidance travels as
 * `help`/`url` on failures produced by stack-auth, but this package reaches CTS
 * over plain HTTP. Depending on `@cipherstash/auth` solely for its lookup would
 * also pull platform binaries into middleware that otherwise has no
 * CipherStash runtime dependency. Preserve that boundary: propagate the code
 * and let the caller choose its own guidance.
 */
async function ctsRefusalError(
  response: Response,
): Promise<{ error: string; authCode?: string }> {
  const raw = await response.text().catch(() => '')
  const { authCode, description } = readCtsRefusal(response.status, raw)

  // Prefer the service's own `error_description` over the whole envelope: on a
  // classified refusal it is the sentence a human wants, and quoting the raw
  // JSON around it adds nothing a caller cannot get from `authCode`.
  const body = (description ?? raw.trim()).slice(0, MAX_BODY_CHARS)

  const context = `Failed to fetch CTS token: the CipherStash API returned ${response.status}`

  return {
    error: body ? `${context}: ${body}` : `${context}.`,
    ...(authCode ? { authCode } : {}),
  }
}

/**
 * Extracts the workspace ID from a CRN string.
 * CRN format: crn:region.aws:ID
 *
 * @param crn The CRN string to extract from
 * @returns The workspace ID portion of the CRN
 */
function extractWorkspaceIdFromCrn(crn: string): string {
  const match = crn.match(/crn:[^:]+:([^:]+)$/)
  if (!match) {
    throw new Error('Invalid CRN format')
  }
  return match[1]
}

export function loadWorkSpaceId(suppliedCrn?: string): string {
  if (suppliedCrn) {
    return extractWorkspaceIdFromCrn(suppliedCrn)
  }

  if (!process.env.CS_WORKSPACE_CRN) {
    throw new Error(
      'You have not defined a workspace CRN in your config file, or the CS_WORKSPACE_CRN environment variable.',
    )
  }

  return extractWorkspaceIdFromCrn(process.env.CS_WORKSPACE_CRN)
}

// Can be used independently of the Next.js middleware
export const fetchCtsToken = async (oidcToken: string): GetCtsTokenResponse => {
  const workspaceId = loadWorkSpaceId()

  if (!workspaceId) {
    logger.error(
      'The "CS_WORKSPACE_ID" environment variable is not set, and is required by protectClerkMiddleware. No CipherStash session will be set.',
    )

    return {
      success: false,
      error: 'The "CS_WORKSPACE_ID" environment variable is not set.',
    }
  }

  const ctsEndoint =
    process.env.CS_CTS_ENDPOINT ||
    'https://ap-southeast-2.aws.auth.viturhosted.net'

  const ctsResponse = await fetch(`${ctsEndoint}/api/authorize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      workspaceId,
      oidcToken,
    }),
  })

  // `fetch` only rejects on a transport failure, so a CTS refusal RESOLVES:
  // a `402` carrying `cs_code: USAGE_LIMIT_EXCEEDED` arrives here as an
  // ordinary response and
  // has to be read off the status.
  if (!ctsResponse.ok) {
    const failure = await ctsRefusalError(ctsResponse)

    logger.debug(failure.error)

    // The blanket "please contact support" this used to end on was wrong for the
    // failure most worth telling apart: a billing refusal is cleared by a human
    // with a billing page, not by a support ticket, and no amount of retrying
    // moves it. The reason now travels with the message instead.
    logger.error(
      `There was an issue communicating with the CipherStash CTS API, the CipherStash session was not set. ${failure.error}`,
    )

    return {
      success: false,
      ...failure,
    }
  }

  const cts_token = (await ctsResponse.json()) as CtsToken

  return {
    success: true,
    ctsToken: cts_token,
  }
}

// Used in the Next.js middleware
export const setCtsToken = async (oidcToken: string, res?: NextResponse) => {
  const ctsResponse = await fetchCtsToken(oidcToken)
  const cts_token = ctsResponse.ctsToken

  if (!cts_token) {
    // No re-prefixing: `error` already opens with "Failed to fetch CTS token"
    // and now carries the status, what CTS said, and any refusal code with it.
    const reason = ctsResponse.error ?? 'no reason was reported'

    logger.debug(reason)

    // Same reasoning as `fetchCtsToken` above: the reason travels with the
    // message rather than a blanket instruction to contact support, which is the
    // wrong advice for a refusal only a billing change can clear.
    logger.error(
      `There was an issue fetching the CipherStash session, the CipherStash session was not set. ${reason}`,
    )

    return res ?? NextResponse.next()
  }

  // Setting cookies on the request and response using the `ResponseCookies` API
  const response = res ?? NextResponse.next()
  response.cookies.set({
    name: CS_COOKIE_NAME,
    value: JSON.stringify(cts_token),
    expires: new Date(cts_token.expiry * 1000),
    sameSite: 'lax',
    path: '/',
  })

  return response
}
