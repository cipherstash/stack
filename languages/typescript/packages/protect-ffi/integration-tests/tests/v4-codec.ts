import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import type { Client } from 'pg'

// EQL v4 has one producer, Stack Encrypt, and it is reached from Rust and Go
// only: no TypeScript SDK writes `v: 4` yet. The migration suites
// (`migrate-v*-to-v4.test.ts`) therefore decrypt legacy rows here with
// protect-ffi and re-encrypt the plaintexts through a small Rust codec,
// `packages/eql/tests/encryption/examples/v4_codec.rs`. It encrypts each value
// through Stack Encrypt's typed API, under the column the value came from, as
// a Rust application migrating its own data would, over live ZeroKMS and the
// same `CS_*` credentials as protect-ffi. Each request list is one ZeroKMS
// call.
//
// Built by `mise run eql:v4:codec` (part of `mise run setup`), under
// `CARGO_TARGET_DIR` when that is set. Set `EQL_V4_CODEC` to use a binary
// somewhere else.

const eqlRoot = resolve(__dirname, '../../../../../../packages/eql')

/** Where the codec is, given the environment the suite runs in. */
export function codecPathFor(env: NodeJS.ProcessEnv): string {
  if (env.EQL_V4_CODEC) return env.EQL_V4_CODEC
  // `eql:v4:codec` runs cargo from `packages/eql`, and cargo resolves a
  // relative `CARGO_TARGET_DIR` against its working directory; `resolve`
  // keeps an absolute one as it is.
  const targetDir = resolve(eqlRoot, env.CARGO_TARGET_DIR || 'target')
  return resolve(targetDir, 'debug/examples/v4_codec')
}

export const codecPath = codecPathFor(process.env)

/**
 * An EQL v4 type name, e.g. `TextEq`: one of the variants of the codec's
 * `Encrypt` enum. `Query` has no `Boolean`, which answers no query.
 */
export type V4Type =
  | 'Boolean'
  | 'IntegerOrdOpe'
  | 'IntegerOrdOre'
  | 'TextEq'
  | 'TextMatch'

export type Plaintext = string | number | boolean

export type V4Item = {
  type: V4Type
  table: string
  column: string
  value: Plaintext
}

export type V4Payload = { v: 4; i: { t: string; c: string } } & Record<
  string,
  unknown
>

type Request = {
  encrypt?: V4Item[]
  query?: V4Item[]
  decrypt?: {
    type: V4Type
    table: string
    column: string
    payload: unknown
  }[]
}

type Response = {
  encrypt: V4Payload[]
  query: V4Payload[]
  decrypt: Plaintext[]
}

const CODEC_TIMEOUT_MS = 60_000

function run(request: Request): Response {
  if (!existsSync(codecPath)) {
    throw new Error(
      `EQL v4 codec not found at ${codecPath}. Build it with \`mise run eql:v4:codec\` from languages/typescript/packages/protect-ffi, or set EQL_V4_CODEC.`,
    )
  }
  const result = spawnSync(codecPath, {
    input: JSON.stringify(request),
    encoding: 'utf8',
    env: process.env,
    maxBuffer: 64 * 1024 * 1024,
    // The codec authenticates against live ZeroKMS. `spawnSync` blocks the
    // event loop, so vitest's own timeout cannot interrupt a stall; this does.
    timeout: CODEC_TIMEOUT_MS,
    killSignal: 'SIGKILL',
  })
  if (result.error) {
    if ((result.error as NodeJS.ErrnoException).code === 'ETIMEDOUT') {
      throw new Error(
        `EQL v4 codec did not finish within ${CODEC_TIMEOUT_MS / 1000}s and was killed.`,
      )
    }
    throw result.error
  }
  if (result.status !== 0) {
    throw new Error(
      `EQL v4 codec exited ${result.status}: ${result.stderr.trim()}`,
    )
  }
  return JSON.parse(result.stdout) as Response
}

/** Encrypt each item as the stored EQL v4 payload for its type. */
export function encryptV4(items: V4Item[]): V4Payload[] {
  if (items.length === 0) return []
  return run({ encrypt: items }).encrypt
}

/**
 * The term-only EQL v4 query operand for each item. Bind it as the type's
 * query domain, e.g. `$1::jsonb::eql_v4.query_text_eq`.
 */
export function queryV4(items: V4Item[]): V4Payload[] {
  if (items.length === 0) return []
  return run({ query: items }).query
}

/**
 * Decrypt stored EQL v4 payloads. Throws when Stack Encrypt refuses one,
 * which is what a payload from any other producer gets.
 */
export function decryptV4(
  items: { type: V4Type; table: string; column: string; payload: unknown }[],
): Plaintext[] {
  if (items.length === 0) return []
  return run({ decrypt: items }).decrypt
}

/**
 * Fail with a setup hint unless EQL v4 is installed next to the legacy
 * version the suite migrates from.
 */
export async function requireEqlV4(pg: Client): Promise<void> {
  const res = await pg.query<{ installed: boolean }>(
    "SELECT to_regnamespace('eql_v4') IS NOT NULL AS installed",
  )
  if (!res.rows[0]?.installed) {
    throw new Error(
      'EQL v4 is not installed. Run `mise run eql:v4:install` from languages/typescript/packages/protect-ffi.',
    )
  }
}

/** SQLSTATE `check_violation`: a payload of the wrong version for a domain. */
export const CHECK_VIOLATION = '23514'
