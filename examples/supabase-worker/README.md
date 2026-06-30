# CipherStash Protect in a Supabase Edge Function

A minimal demo of using [`@cipherstash/stack`](https://www.npmjs.com/package/@cipherstash/stack) inside a Supabase Edge Function. The function encrypts a hardcoded plaintext value with CipherStash Protect, decrypts it back, and returns the round-trip result as JSON.

The function imports from the `@cipherstash/stack/wasm-inline` subpath — the WASM build of Protect, with the WASM module inlined into the JS bundle. No native bindings are loaded, so it works in Supabase Edge (Deno) and any other V8-only runtime (Cloudflare Workers, Bun, modern browsers).

## Prerequisites

- Node ≥ 22 and pnpm 10 (matches the repo root); only needed for the local install step.
- A CipherStash workspace + service-to-service credentials (client ID, client key, access key) — see the [CipherStash docs](https://cipherstash.com/docs).
- [Supabase CLI](https://supabase.com/docs/guides/cli) installed locally.

## Install

This example has no compile step — the Edge runtime resolves `npm:` specifiers at function start. The `pnpm install` below only wires up workspace metadata (no runtime dependencies):

```sh
pnpm install
```

## Run locally

```sh
cp .env.example .env.local
# fill in CS_WORKSPACE_CRN, CS_CLIENT_ID, CS_CLIENT_KEY, CS_CLIENT_ACCESS_KEY

supabase functions serve --env-file .env.local cipherstash-roundtrip
```

In another shell:

```sh
curl -s http://localhost:54321/functions/v1/cipherstash-roundtrip | jq
```

Expected response:

```json
{
  "ok": true,
  "plaintext": "alice@example.com",
  "decrypted": "alice@example.com",
  "isEncrypted": true,
  "ciphertextIdentifier": { "t": "users", "c": "email" }
}
```

## Deploy

```sh
supabase functions deploy cipherstash-roundtrip
supabase secrets set --env-file .env.local
```

## Native modules

There are none. The `@cipherstash/stack/wasm-inline` subpath embeds the protect-ffi WASM module as base64 inside its JS bundle and pulls `AccessKeyStrategy` from `@cipherstash/auth/wasm-inline` (also pure WASM). No `node-gyp`, no `.node` binaries, no platform-specific install scripts.

## What this verifies

- Protect's WASM build works inside Supabase Edge Functions.
- The full `@cipherstash/stack/wasm-inline` developer surface (`Encryption`, `encryptedTable`, `encryptedColumn`, …) is usable from an Edge Function with no native dependencies.
- A CipherStash service-to-service `AccessKeyStrategy` is the right credential shape for serverless / edge environments.

Automated coverage of the same code path lives at `e2e/wasm/roundtrip.test.ts` and runs in CI on every PR — this example is the runnable runbook version.
