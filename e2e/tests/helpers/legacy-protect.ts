/**
 * Shared plumbing for the suites that pin compatibility with the Protect.js
 * stack customers still run: `@cipherstash/protect@10.2.1` (→
 * `@cipherstash/protect-ffi@0.18.1` → cipherstash-client 0.28) and
 * `@cipherstash/protect-dynamodb@6.0.1`.
 */
import { fileURLToPath } from 'node:url'
import { protect } from '@cipherstash/protect'
import { config } from 'dotenv'

// A local `.env` in `e2e/` or at the repo root, as AGENTS.md describes. CI
// injects the variables directly; an existing value always wins.
config({
  path: ['../../.env', '../../../.env'].map((p) =>
    fileURLToPath(new URL(p, import.meta.url)),
  ),
  quiet: true,
})

export const authConfigured = Boolean(
  process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)

/**
 * Build Protect's native client (cipherstash-client 0.28) for the same
 * workspace Stack uses.
 *
 * Unlike today's clients, 0.28 does not derive its service hosts from the
 * workspace CRN: with no override it defaults to the legacy
 * `ap-southeast-2.aws.auth.viturhosted.net`, so a workspace in another region
 * gets a 401 from CTS. So point `CS_CTS_HOST` / `CS_ZEROKMS_HOST` at the CRN's
 * region while the client is built, using the URLs current clients derive by
 * service discovery (cts-common's `CtsServiceDiscovery` and
 * `ZeroKmsServiceDiscovery`), then restore them: the hosts are read at
 * construction, and Stack's client must keep deriving its own. Credentials
 * are passed explicitly, as a Protect app configured from these variables
 * would.
 */
export async function legacyProtect(
  schemas: Parameters<typeof protect>[0]['schemas'],
) {
  const crn = process.env.CS_WORKSPACE_CRN as string
  const region = crn.split(':')[1]
  const saved = {
    CS_CTS_HOST: process.env.CS_CTS_HOST,
    CS_ZEROKMS_HOST: process.env.CS_ZEROKMS_HOST,
  }
  process.env.CS_CTS_HOST = `https://${region}.cts.cipherstashmanaged.net`
  process.env.CS_ZEROKMS_HOST = `https://${region}.viturhosted.net`
  try {
    return await protect({
      schemas,
      workspaceCrn: crn,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
    })
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

/** Unwrap a `{ data } | { failure }` result, failing the test on `failure`. */
export function ok<T>(
  result: { data: T; failure?: undefined } | { failure: unknown },
  label: string,
): T {
  if ('failure' in result && result.failure !== undefined) {
    const failure = result.failure as { message?: unknown }
    // An Error's message is not enumerable, so JSON.stringify alone drops it.
    throw new Error(
      `${label} failed: ${String(failure?.message ?? '')} ${JSON.stringify(failure)}`,
    )
  }
  return (result as { data: T }).data
}
