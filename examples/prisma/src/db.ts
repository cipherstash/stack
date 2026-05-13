/**
 * Wire the Prisma Next Postgres runtime with the cipherstash extension
 * in one call.
 *
 * `cipherstashFromStack({ contractJson })` derives the encryption
 * schemas from the contract, constructs the `@cipherstash/stack`
 * `EncryptionClient` against your `CS_*` env vars, builds the SDK
 * adapter, and returns ready-to-spread arrays for `extensions` and
 * `middleware`. Override `schemas` only if you have additional tables
 * the contract does not model.
 */

import 'dotenv/config'

import { cipherstashFromStack } from '@cipherstash/prisma-next/stack'
import postgres from '@prisma-next/postgres/runtime'

import type { Contract } from './prisma/contract.d'
import contractJson from './prisma/contract.json' with { type: 'json' }

const cipherstash = await cipherstashFromStack({ contractJson })

export const db = postgres<Contract>({
  contractJson,
  extensions: cipherstash.extensions,
  middleware: cipherstash.middleware,
})
