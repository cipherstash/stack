/**
 * TLS-aware `pg.ClientConfig` construction — the policy half of the CLI's
 * database connections. Runtime-import-free on `pg` (type-only), so the
 * offline-capable commands that lazy-load the driver (`eql repair`'s applied
 * probe) can build a config without pulling `pg` in. The convenience factory
 * lives in `./client.ts`.
 *
 * node-postgres does two things we can't ship as-is in a security product:
 *
 * 1. It treats `sslmode=prefer|require|verify-ca` as aliases for
 *    `verify-full` and prints a process-level SECURITY WARNING saying so on
 *    every invocation against such URLs (#822). We keep the verify-full
 *    semantics but decide them ourselves, handing pg an explicit `ssl`
 *    config and a URL with the TLS params stripped — same behaviour, no
 *    upstream advisory on our stdout.
 *
 * 2. It has no CA story. Managed providers (Supabase) sign their server
 *    certificates with a private CA, so verification fails with
 *    `self-signed certificate in certificate chain` and the only
 *    discoverable fix used to be `NODE_TLS_REJECT_UNAUTHORIZED=0` —
 *    process-wide, covering the connections that carry ZeroKMS credentials
 *    (#889). We honour `sslrootcert` (and `PGSSLROOTCERT`), bundle the
 *    Supabase root CA for `*.supabase.co|com` hosts, and shape cert errors
 *    into the supported remedies.
 *
 * URLs with no `sslmode`/`sslrootcert` at all — and URLs using client
 * certificates (`sslcert`/`sslkey`) or the raw `ssl` param — pass through
 * untouched: zero behaviour change outside the parameters we understand.
 */

import { readFileSync } from 'node:fs'
import tls from 'node:tls'
import type pg from 'pg'
import { SUPABASE_ROOT_CA_PEM } from './supabase-ca.js'

/** Hosts the bundled Supabase root CA applies to (db.* and pooler.*). */
const SUPABASE_HOST_PATTERN = /\.supabase\.(?:co|com)$/i

/** Params this module consumes; everything else stays on the URL. */
const HANDLED_PARAMS = ['sslmode', 'sslrootcert'] as const

/** Params that mean "hand-tuned TLS setup — don't touch the URL". */
const PASSTHROUGH_PARAMS = ['sslcert', 'sslkey', 'sslpassword', 'ssl'] as const

/** The PGSSLMODE values node-postgres itself recognises — mirrored exactly. */
const ENV_SSLMODES = [
  'disable',
  'prefer',
  'require',
  'verify-ca',
  'verify-full',
  'no-verify',
]

let warnedNoVerify = false

/** Test hook: reset the once-per-process no-verify warning. */
export function resetNoVerifyWarningForTests(): void {
  warnedNoVerify = false
}

export function buildPgClientConfig(
  databaseUrl: string,
  extra: Omit<pg.ClientConfig, 'connectionString' | 'ssl'> = {},
): pg.ClientConfig {
  let url: URL
  try {
    url = new URL(databaseUrl)
  } catch {
    // Not URL-parseable (e.g. a bare socket path) — let pg have it verbatim.
    return { ...extra, connectionString: databaseUrl }
  }

  const params = url.searchParams
  if (PASSTHROUGH_PARAMS.some((name) => params.has(name))) {
    return { ...extra, connectionString: databaseUrl }
  }
  let sslmode = params.get('sslmode')
  const sslrootcert = params.get('sslrootcert')
  if (sslmode === null && sslrootcert === null) {
    // Environment tier, mirroring node-postgres's own PGSSLMODE handling
    // (connection-parameters.js `readSSLConfigFromEnvironment`) — pg enables
    // TLS from this variable but ignores PGSSLROOTCERT entirely, so without
    // taking this branch ourselves an env-configured connection would verify
    // against the wrong trust anchors. URL parameters win when present
    // (libpq precedence); an unset or unrecognised PGSSLMODE stays a pure
    // passthrough.
    const envMode = process.env.PGSSLMODE
    if (envMode !== undefined && ENV_SSLMODES.includes(envMode)) {
      sslmode = envMode
    } else {
      return { ...extra, connectionString: databaseUrl }
    }
  }

  for (const name of HANDLED_PARAMS) params.delete(name)
  const stripped = url.toString()

  if (sslmode === 'disable') {
    return { ...extra, connectionString: stripped, ssl: false }
  }

  if (sslmode === 'no-verify') {
    if (!warnedNoVerify) {
      warnedNoVerify = true
      process.stderr.write(
        'stash: sslmode=no-verify — the connection to the database is encrypted but the server is NOT authenticated. Prefer sslmode=verify-full with sslrootcert=<your provider CA>.\n',
      )
    }
    return {
      ...extra,
      connectionString: stripped,
      ssl: { rejectUnauthorized: false },
    }
  }

  // Everything else — `require`, `verify-ca`, `prefer`, `verify-full`, or a
  // bare `sslrootcert` — verifies fully, which is what node-postgres already
  // did for these modes (its "aliases for verify-full" advisory). We are
  // preserving behaviour, not tightening it.
  return {
    ...extra,
    connectionString: stripped,
    ssl: { rejectUnauthorized: true, ca: resolveCa(sslrootcert, url.hostname) },
  }
}

/**
 * CA resolution, first hit wins:
 *
 * 1. `sslrootcert=<path>` from the URL — libpq semantics: the named file is
 *    the ONLY trust anchor. `sslrootcert=system` selects the system store.
 * 2. `PGSSLROOTCERT` env — same semantics.
 * 3. A Supabase host — the bundled Supabase root CA, APPENDED to the system
 *    roots so publicly-signed certificates keep verifying.
 * 4. Otherwise the system trust store (`ca: undefined`).
 */
function resolveCa(
  sslrootcert: string | null,
  hostname: string,
): string | string[] | undefined {
  const explicit = sslrootcert ?? process.env.PGSSLROOTCERT?.trim()
  if (explicit) {
    if (explicit === 'system') return undefined
    try {
      return readFileSync(explicit, 'utf-8')
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(
        `Cannot read the CA file named by sslrootcert (${explicit}): ${detail}`,
        { cause: error },
      )
    }
  }
  if (SUPABASE_HOST_PATTERN.test(hostname)) {
    return [...tls.rootCertificates, SUPABASE_ROOT_CA_PEM]
  }
  return undefined
}

/** Error codes / messages that mean "certificate verification failed". */
const TLS_FAILURE_PATTERNS = [
  'SELF_SIGNED_CERT_IN_CHAIN',
  'self-signed certificate',
  'self signed certificate',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'unable to verify the first certificate',
  'UNABLE_TO_GET_ISSUER_CERT',
  'unable to get local issuer certificate',
  'CERT_HAS_EXPIRED',
  'certificate has expired',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'Hostname/IP does not match',
]

/**
 * A certificate-verification failure, re-thrown by the factory's connect
 * wrapper with the shaped remedy as its message. Call sites that add their
 * own "Failed to connect" framing should rethrow/print this one verbatim —
 * the message is self-contained, and re-shaping it nests explanations.
 */
export class TlsVerificationError extends Error {}

/**
 * When `error` is a certificate-verification failure, return a message that
 * names the host and the supported remedies in order — so the discoverable
 * fix is never `NODE_TLS_REJECT_UNAUTHORIZED=0` (process-wide: it would also
 * disable verification for the connections carrying ZeroKMS credentials).
 * Returns null for anything that is not a TLS trust failure.
 */
export function explainTlsError(
  error: unknown,
  databaseUrl: string,
): string | null {
  const err = error as { code?: unknown; message?: unknown } | null
  const code = typeof err?.code === 'string' ? err.code : ''
  const message = typeof err?.message === 'string' ? err.message : ''
  const matched = TLS_FAILURE_PATTERNS.some(
    (pattern) => code === pattern || message.includes(pattern),
  )
  if (!matched) return null

  let host = 'the database host'
  try {
    host = new URL(databaseUrl).hostname || host
  } catch {
    // keep the placeholder
  }
  return [
    `TLS certificate verification failed for ${host}: ${message || code}.`,
    'Fixes, in order of preference:',
    "  1. Verify against your provider's CA: append sslrootcert=/path/to/ca.pem to the connection string (or set PGSSLROOTCERT). Supabase hosts are already covered by the CLI's bundled Supabase root CA.",
    '  2. Last resort: sslmode=no-verify keeps the connection encrypted but skips server authentication for THIS connection only.',
    'Never set NODE_TLS_REJECT_UNAUTHORIZED=0 — it disables TLS verification for every connection in the process, including the ones carrying CipherStash credentials.',
  ].join('\n')
}
