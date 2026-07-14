/**
 * Wire the Prisma Next Postgres runtime with the cipherstash EQL v3
 * extension in one call.
 *
 * `cipherstashFromStackV3({ contractJson })` derives the v3 encryption
 * schemas from the contract (one `public.eql_v3_*` domain per column),
 * constructs the `@cipherstash/stack` `EncryptionV3` client against
 * your `CS_*` env vars or local profile, builds the SDK adapter, and
 * returns ready-to-spread arrays for `extensions` and `middleware`.
 * Override `schemasV3` only if you have additional tables the contract
 * does not model.
 *
 * A v3 client is v3-only: a contract carrying v2 cipherstash codec ids
 * is rejected at setup (use `cipherstashFromStack` from
 * `@cipherstash/prisma-next/stack` for a v2 contract).
 */

import 'dotenv/config'

import { cipherstashFromStackV3 } from '@cipherstash/prisma-next/v3'
import postgres from '@prisma-next/postgres/runtime'

import type { Contract } from './prisma/contract.d'
import contractJson from './prisma/contract.json' with { type: 'json' }

const cipherstash = await cipherstashFromStackV3({ contractJson })

export const db = postgres<Contract>({
  contractJson,
  extensions: cipherstash.extensions,
  middleware: cipherstash.middleware,
})
