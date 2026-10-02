import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import tls from 'node:tls'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  buildPgClientConfig,
  explainTlsError,
  resetNoVerifyWarningForTests,
} from '../config.js'
import { SUPABASE_ROOT_CA_PEM } from '../supabase-ca.js'

type SslObject = { rejectUnauthorized?: boolean; ca?: string | string[] }

function ssl(config: ReturnType<typeof buildPgClientConfig>): SslObject {
  expect(config.ssl).toBeTypeOf('object')
  return config.ssl as SslObject
}

describe('buildPgClientConfig', () => {
  beforeEach(() => {
    resetNoVerifyWarningForTests()
    vi.unstubAllEnvs()
  })
  afterEach(() => vi.restoreAllMocks())

  it('passes a URL with no TLS params through untouched', () => {
    const url = 'postgres://user:pass@db.example.com:5432/app'
    expect(buildPgClientConfig(url)).toEqual({ connectionString: url })
  })

  it('passes non-URL connection strings through untouched', () => {
    expect(buildPgClientConfig('not a url')).toEqual({
      connectionString: 'not a url',
    })
  })

  it('passes client-certificate setups through untouched', () => {
    const url =
      'postgres://u@db.example.com/app?sslmode=verify-full&sslcert=c.pem&sslkey=k.pem'
    expect(buildPgClientConfig(url)).toEqual({ connectionString: url })
  })

  it('merges extra client options in every arm', () => {
    const plain = buildPgClientConfig('postgres://u@h/app', {
      connectionTimeoutMillis: 10_000,
    })
    expect(plain.connectionTimeoutMillis).toBe(10_000)
    const tlsful = buildPgClientConfig('postgres://u@h/app?sslmode=require', {
      connectionTimeoutMillis: 10_000,
    })
    expect(tlsful.connectionTimeoutMillis).toBe(10_000)
  })

  it('sslmode=disable turns TLS off and strips the param', () => {
    const config = buildPgClientConfig(
      'postgres://u@db.example.com/app?sslmode=disable',
    )
    expect(config.ssl).toBe(false)
    expect(config.connectionString).not.toContain('sslmode')
  })

  it('sslmode=no-verify keeps encryption without verification, warning once on stderr', () => {
    const stderr = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true)
    const first = buildPgClientConfig(
      'postgres://u@db.example.com/app?sslmode=no-verify',
    )
    expect(ssl(first).rejectUnauthorized).toBe(false)
    buildPgClientConfig('postgres://u@db.example.com/app?sslmode=no-verify')
    expect(stderr).toHaveBeenCalledTimes(1)
    expect(String(stderr.mock.calls[0]?.[0])).toContain('NOT authenticated')
  })

  it.each(['require', 'prefer', 'verify-ca', 'verify-full'])(
    'sslmode=%s verifies fully and strips the param',
    (mode) => {
      const config = buildPgClientConfig(
        `postgres://u@db.example.com/app?sslmode=${mode}`,
      )
      expect(ssl(config).rejectUnauthorized).toBe(true)
      expect(config.connectionString).not.toContain('sslmode')
    },
  )

  it('honours sslrootcert=<path> as the sole trust anchor (libpq semantics)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'stash-ca-'))
    const caPath = join(dir, 'root.pem')
    writeFileSync(caPath, 'FAKE PEM CONTENT')
    const config = buildPgClientConfig(
      `postgres://u@db.example.com/app?sslmode=verify-full&sslrootcert=${caPath}`,
    )
    expect(ssl(config).ca).toBe('FAKE PEM CONTENT')
    expect(config.connectionString).not.toContain('sslrootcert')
  })

  it('sslrootcert=system selects the system trust store', () => {
    const config = buildPgClientConfig(
      'postgres://u@db.example.com/app?sslmode=verify-full&sslrootcert=system',
    )
    expect(ssl(config).rejectUnauthorized).toBe(true)
    expect(ssl(config).ca).toBeUndefined()
  })

  it('fails loudly when the sslrootcert file cannot be read', () => {
    expect(() =>
      buildPgClientConfig(
        'postgres://u@db.example.com/app?sslmode=verify-full&sslrootcert=/nonexistent/ca.pem',
      ),
    ).toThrow(/Cannot read the CA file named by sslrootcert/)
  })

  it('falls back to PGSSLROOTCERT when the URL names no CA', () => {
    const dir = mkdtempSync(join(tmpdir(), 'stash-ca-'))
    const caPath = join(dir, 'env.pem')
    writeFileSync(caPath, 'ENV PEM')
    vi.stubEnv('PGSSLROOTCERT', caPath)
    const config = buildPgClientConfig(
      'postgres://u@db.example.com/app?sslmode=require',
    )
    expect(ssl(config).ca).toBe('ENV PEM')
  })

  it('appends the bundled Supabase root CA to the system roots for Supabase hosts', () => {
    for (const host of [
      'db.abcdefghij.supabase.co',
      'aws-0-us-east-1.pooler.supabase.com',
    ]) {
      const config = buildPgClientConfig(
        `postgres://u@${host}:5432/postgres?sslmode=require`,
      )
      const ca = ssl(config).ca
      expect(Array.isArray(ca)).toBe(true)
      expect(ca).toContain(SUPABASE_ROOT_CA_PEM)
      expect((ca as string[]).length).toBe(tls.rootCertificates.length + 1)
    }
  })

  it('does not attach the Supabase CA to non-Supabase hosts', () => {
    const config = buildPgClientConfig(
      'postgres://u@db.example.com/app?sslmode=require',
    )
    expect(ssl(config).ca).toBeUndefined()
  })

  it('a bare sslrootcert with no sslmode still verifies fully', () => {
    const dir = mkdtempSync(join(tmpdir(), 'stash-ca-'))
    const caPath = join(dir, 'bare.pem')
    writeFileSync(caPath, 'BARE PEM')
    const config = buildPgClientConfig(
      `postgres://u@db.example.com/app?sslrootcert=${caPath}`,
    )
    expect(ssl(config).rejectUnauthorized).toBe(true)
    expect(ssl(config).ca).toBe('BARE PEM')
  })
})

describe('PGSSLMODE environment tier', () => {
  beforeEach(() => {
    resetNoVerifyWarningForTests()
    vi.unstubAllEnvs()
  })

  it('enables verification from PGSSLMODE=require, with CA resolution', () => {
    vi.stubEnv('PGSSLMODE', 'require')
    const config = buildPgClientConfig(
      'postgres://u@aws-0-us-east-1.pooler.supabase.com:5432/postgres',
    )
    expect(ssl(config).rejectUnauthorized).toBe(true)
    // The whole point over pg's own env handling: the CA tier runs, so the
    // bundled Supabase root applies (pg ignores PGSSLROOTCERT entirely).
    expect(ssl(config).ca).toContain(SUPABASE_ROOT_CA_PEM)
  })

  it('honours PGSSLROOTCERT alongside PGSSLMODE', () => {
    const dir = mkdtempSync(join(tmpdir(), 'stash-ca-'))
    const caPath = join(dir, 'env-tier.pem')
    writeFileSync(caPath, 'ENV TIER PEM')
    vi.stubEnv('PGSSLMODE', 'verify-full')
    vi.stubEnv('PGSSLROOTCERT', caPath)
    const config = buildPgClientConfig('postgres://u@db.example.com/app')
    expect(ssl(config).rejectUnauthorized).toBe(true)
    expect(ssl(config).ca).toBe('ENV TIER PEM')
  })

  it('mirrors pg for PGSSLMODE=disable and no-verify', () => {
    vi.stubEnv('PGSSLMODE', 'disable')
    expect(buildPgClientConfig('postgres://u@h/app').ssl).toBe(false)
    vi.stubEnv('PGSSLMODE', 'no-verify')
    const stderr = vi
      .spyOn(process.stderr, 'write')
      .mockImplementation(() => true)
    expect(
      ssl(buildPgClientConfig('postgres://u@h/app')).rejectUnauthorized,
    ).toBe(false)
    expect(stderr).toHaveBeenCalledTimes(1)
  })

  it('passes through on an unrecognised PGSSLMODE, exactly like pg', () => {
    vi.stubEnv('PGSSLMODE', 'allow')
    const url = 'postgres://u@h/app'
    expect(buildPgClientConfig(url)).toEqual({ connectionString: url })
  })

  it('lets URL parameters beat the environment (libpq precedence)', () => {
    vi.stubEnv('PGSSLMODE', 'require')
    const config = buildPgClientConfig('postgres://u@h/app?sslmode=disable')
    expect(config.ssl).toBe(false)
  })
})

describe('explainTlsError', () => {
  const url = 'postgres://u@aws-0-ap-southeast-2.pooler.supabase.com/postgres'

  it('names the host and the remedies for a self-signed chain', () => {
    const explanation = explainTlsError(
      Object.assign(new Error('self-signed certificate in certificate chain'), {
        code: 'SELF_SIGNED_CERT_IN_CHAIN',
      }),
      url,
    )
    expect(explanation).toContain('aws-0-ap-southeast-2.pooler.supabase.com')
    expect(explanation).toContain('sslrootcert=')
    expect(explanation).toContain('sslmode=no-verify')
    expect(explanation).toContain('Never set NODE_TLS_REJECT_UNAUTHORIZED=0')
  })

  it('recognises hostname-mismatch failures', () => {
    expect(
      explainTlsError(
        Object.assign(
          new Error("Hostname/IP does not match certificate's altnames"),
          {
            code: 'ERR_TLS_CERT_ALTNAME_INVALID',
          },
        ),
        url,
      ),
    ).not.toBeNull()
  })

  it('returns null for non-TLS failures', () => {
    expect(
      explainTlsError(new Error('password authentication failed'), url),
    ).toBeNull()
    expect(explainTlsError(new Error('ECONNREFUSED'), url)).toBeNull()
    expect(explainTlsError(null, url)).toBeNull()
  })
})
