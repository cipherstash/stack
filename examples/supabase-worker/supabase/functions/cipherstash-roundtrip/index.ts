/// <reference types="https://esm.sh/@supabase/functions-js/src/edge-runtime.d.ts" />
/**
 * Supabase Edge Function demo: encrypt a value with CipherStash Protect
 * and decrypt it back, all via WASM (no native bindings).
 *
 * Imports `@cipherstash/stack/wasm-inline` — the WASM-inline subpath
 * works in any V8-only runtime (Supabase Edge, Cloudflare Workers, Bun,
 * Deno, modern browsers).
 *
 * Usage:
 *   cp ../../.env.example ../../.env.local   # fill in your CS_* values
 *   supabase functions serve --env-file ../../.env.local cipherstash-roundtrip
 *   curl http://localhost:54321/functions/v1/cipherstash-roundtrip
 */

import {
  Encryption,
  encryptedColumn,
  encryptedTable,
  isEncrypted,
} from 'npm:@cipherstash/stack@^0.18.0/wasm-inline'

const users = encryptedTable('users', {
  email: encryptedColumn('email').equality(),
})

Deno.serve(async (_req: Request) => {
  const accessKey = Deno.env.get('CS_CLIENT_ACCESS_KEY')
  const clientId = Deno.env.get('CS_CLIENT_ID')
  const clientKey = Deno.env.get('CS_CLIENT_KEY')
  const workspaceCrn = Deno.env.get('CS_WORKSPACE_CRN')

  const missing = Object.entries({
    CS_WORKSPACE_CRN: workspaceCrn,
    CS_CLIENT_ACCESS_KEY: accessKey,
    CS_CLIENT_ID: clientId,
    CS_CLIENT_KEY: clientKey,
  })
    .filter(([, v]) => !v)
    .map(([k]) => k)

  if (missing.length > 0) {
    return Response.json(
      {
        error: `missing env vars: ${missing.join(', ')}`,
        hint: 'Pass via `supabase functions serve --env-file .env.local`',
      },
      { status: 400 },
    )
  }

  try {
    const client = await Encryption({
      schemas: [users],
      config: {
        workspaceCrn: workspaceCrn!,
        accessKey: accessKey!,
        clientId: clientId!,
        clientKey: clientKey!,
      },
    })

    const plaintext = 'alice@example.com'
    // Every fallible method returns `{ data } | { failure }` — the same
    // contract as the native entry (see AGENTS.md).
    const encryptResult = await client.encrypt(plaintext, {
      column: users.email,
      table: users,
    })
    if (encryptResult.failure) {
      return Response.json(
        { ok: false, error: encryptResult.failure.message },
        { status: 500 },
      )
    }
    const encrypted = encryptResult.data

    const decryptResult = await client.decrypt(encrypted)
    if (decryptResult.failure) {
      return Response.json(
        { ok: false, error: decryptResult.failure.message },
        { status: 500 },
      )
    }
    const decrypted = decryptResult.data

    return Response.json(
      {
        ok: decrypted === plaintext,
        plaintext,
        decrypted,
        isEncrypted: isEncrypted(encrypted),
        ciphertextIdentifier: (encrypted as { i?: unknown }).i,
      },
      { headers: { 'content-type': 'application/json' } },
    )
  } catch (e) {
    // Debug-only response shape — a production handler should never
    // surface error details to callers. The `stack` field is logged
    // for the operator but not returned in the response body.
    const err = e as { code?: string; message?: string; stack?: string }
    console.error('cipherstash-roundtrip failed:', err.stack ?? err.message)
    return Response.json(
      { code: err.code, message: err.message },
      { status: 500 },
    )
  }
})
