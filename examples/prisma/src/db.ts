/**
 * Wire the Prisma Next Postgres runtime with the cipherstash EQL v3
 * extension in one call.
 *
 * `cipherstashFromStack({ contractJson })` derives the v3 encryption
 * schemas from the contract (one `public.eql_v3_*` domain per column),
 * constructs the `@cipherstash/stack` `EncryptionV3` client against
 * your `CS_*` env vars or local profile, builds the SDK adapter, and
 * returns ready-to-spread arrays for `extensions` and `middleware`.
 * Override `schemasV3` only if you have additional tables the contract
 * does not model.
 */

import 'dotenv/config'

import { cipherstashFromStack } from '@cipherstash/prisma-next/v3'
import postgres from '@prisma-next/postgres/runtime'

import type { Contract } from './prisma/contract.d'
import contractJson from './prisma/contract.json' with { type: 'json' }

const cipherstash = await cipherstashFromStack({ contractJson })

export const db = postgres<Contract>({
  contractJson,
  extensions: cipherstash.extensions,
  middleware: cipherstash.middleware,
})
