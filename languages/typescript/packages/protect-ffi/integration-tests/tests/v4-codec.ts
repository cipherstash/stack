import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import type { Client } from 'pg'

// EQL v4 has one producer, Stack Encrypt, and it is reached from Rust and Go
// only: no TypeScript SDK writes `v: 4` yet. The migration suites
// (`migrate-v*-to-v4.test.ts`) therefore decrypt legacy rows here with
// protect-ffi and re-encrypt the plaintexts through a small Rust codec,
// `packages/eql/tests/encryption/examples/v4_codec.rs`. It dispatches on the
// EQL type name through `eql_bindings::encryption::targets`, the same entry
// point the Go guest uses, under live ZeroKMS and the same `CS_*` credentials
// as protect-ffi.
//
// Built by `mise run eql:v4:codec` (part of `mise run setup`). Set
// `EQL_V4_CODEC` to use a binary somewhere else.

const repoRoot = resolve(__dirname, '../../../../../..')

export const codecPath =
  process.env.EQL_V4_CODEC ??
  resolve(repoRoot, 'packages/eql/target/debug/examples/v4_codec')

/** An EQL v4 type name, e.g. `TextEq`, as `targets::targets()` lists it. */
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
  })
  if (result.error) throw result.error
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
