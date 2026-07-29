/**
 * The `Encryption` schema and config typing must survive declaration emit.
 *
 * The gate next door (`encrypt-query.ts`) covers `encryptQuery` narrowing only.
 * That left the other two halves of the #815 acceptance criterion — "Encryption
 * static types agree with runtime for v3 schemas, non-tuple schema arrays, and
 * config typing" — asserted nowhere against the BUILT package, so a regression
 * in either would ship green.
 *
 * The shapes below are the ones real callers hold. A-4 widened the factory to
 * accept them after a mutable non-empty tuple rejected everything that is not
 * an array literal; each is pinned here so the emitted `.d.ts` cannot narrow
 * back without CI noticing.
 */

import { Encryption, encryptedTable, types } from '../dist/encryption/v3.js'
import type { AnyV3Table } from '../dist/eql/v3/index.js'
import type { EncryptionClientConfig } from '../dist/types-public.js'

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
})
const orders = encryptedTable('orders', {
  total: types.IntegerOrd('total'),
})

export async function schemaShapes() {
  // A literal tuple — the baseline.
  await Encryption({ schemas: [users, orders] })

  // A widened array: a shared `export const all: AnyV3Table[]`.
  const widened: AnyV3Table[] = [users, orders]
  await Encryption({ schemas: widened })

  // A readonly array, e.g. what `as const` or a ReadonlyArray field yields.
  const frozen: readonly AnyV3Table[] = [users, orders]
  await Encryption({ schemas: frozen })

  // A `.map()` result — no literal-ness at all.
  await Encryption({ schemas: [users, orders].map((t) => t) })

  // A caller generic over its own schemas (integration adapters do this).
  async function make<S extends readonly [AnyV3Table, ...AnyV3Table[]]>(
    schemas: S,
  ) {
    return Encryption({ schemas })
  }
  await make([users])
}

export async function configShapes() {
  await Encryption({
    schemas: [users],
    config: { workspaceCrn: 'crn', accessKey: 'ak' },
  })

  await Encryption({
    schemas: [users],
    // @ts-expect-error - `eqlVersion` was removed; Stack always authors EQL v3
    config: { eqlVersion: 2 },
  })

  // The same rejection through a hoisted const. Excess-property checking only
  // fires on FRESH object literals, so the shape a v2 → v3 migration most
  // plausibly has — one shared config object — type-checked clean and then
  // threw at runtime. `eqlVersion?: never` on `ClientConfig` makes the two
  // agree; the runtime guard stays for JS/JSON callers who bypass types.
  const hoistedConfig = { workspaceCrn: 'crn', eqlVersion: 2 }
  await Encryption({
    schemas: [users],
    // @ts-expect-error - rejected even when the config is not a fresh literal
    config: hoistedConfig,
  })

  // @ts-expect-error - at least one table is required
  await Encryption({ schemas: [] })
}

/**
 * The same non-emptiness through the EXPORTED config type, which is the shape a
 * caller actually holds when the config is built once and passed around. The
 * inline rejection above only covers a fresh literal: with a default type
 * argument of `readonly AnyV3Table[]`, `S['length']` widens to `number`, the
 * non-empty conditional stops firing, and an empty set type-checked clean here
 * before throwing at `Encryption()`. Asserted against the BUILT declarations
 * because that is what ships.
 */
export async function exportedConfigTypeShapes() {
  // @ts-expect-error - at least one table is required
  const empty: EncryptionClientConfig = { schemas: [] }
  void empty

  const populated: EncryptionClientConfig = { schemas: [users, orders] }
  await Encryption(populated)
}
