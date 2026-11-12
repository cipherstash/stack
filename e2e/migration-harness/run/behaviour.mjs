import { isDeepStrictEqual } from 'node:util'
import { createCheck, equal } from './behaviour-checks.mjs'

export const legacy = {
  pk: 'legacy',
  email: 'Legacy@example.com',
  emailLower: 'LEGACY@example.com',
  age: 42,
  balance: '9007199254740990',
  active: true,
  notes: 'legacy note',
}
export const mutation = {
  ...legacy,
  pk: 'mutation',
  email: 'Mutation@example.com',
  emailLower: 'MUTATION@example.com',
  balance: '-42',
}
export const fresh = {
  ...mutation,
  pk: 'fresh',
  email: 'Fresh@example.com',
  emailLower: 'FRESH@example.com',
}

/** @typedef {(method:string,args:unknown[])=>Promise<unknown>} AppCall
 * @typedef {typeof legacy} Customer */
/** @param {unknown} value @returns {Record<string,unknown>} */
function record(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw Error('Expected application record')
  return Object.fromEntries(Object.entries(value))
}
/** @param {unknown} value @returns {unknown[]} */
function records(value) {
  if (!Array.isArray(value)) throw Error('Expected application records')
  return value
}
/** @param {Customer} customer */
function postgresRecord(customer) {
  return {
    pk: customer.pk,
    email: customer.email,
    age: customer.age,
    notes: customer.notes,
  }
}
/** Compare complete result sets without imposing database row order. Stack may
 * normalize the downcase column when writing the fresh record.
 * @param {unknown} value */
function orderedRows(value) {
  return records(value)
    .map((item) => {
      const row = record(item)
      return row.pk === fresh.pk && typeof row.emailLower === 'string'
        ? { ...row, emailLower: row.emailLower.toLowerCase() }
        : row
    })
    .sort((left, right) => String(left.pk).localeCompare(String(right.pk)))
}
/** Calls only the App Host JSON RPC boundary; never imports application code.
 * @param {AppCall} call
 * @param {()=>Promise<void>} afterSetActive */
export async function behaviour(call, afterSetActive = async () => {}) {
  /** @type {import('../types.js').OracleCheck[]} */
  const checks = []
  const check = createCheck(checks)
  /** @param {string} method @param {unknown} value
   * @param {unknown[]} expected @param {unknown} absent */
  async function lookup(method, value, expected, absent) {
    equal(orderedRows(await call(method, [value])), orderedRows(expected))
    equal(await call(method, [absent]), [])
  }
  await check('behaviour.legacy-get', async () =>
    equal(await call('get', [legacy.pk]), legacy),
  )
  /** @type {[string,unknown,Customer[],unknown][]} */
  const legacyLookups = [
    ['findEmail', legacy.email, [legacy], 'absent@example.com'],
    [
      'findEmailLower',
      legacy.emailLower.toLowerCase(),
      [legacy],
      'absent@example.com',
    ],
    ['findAge', legacy.age, [legacy, mutation], -1],
    ['findBalance', legacy.balance, [legacy], '123456789'],
    ['findActive', legacy.active, [legacy, mutation], false],
  ]
  for (const [method, value, expected, absent] of legacyLookups) {
    await check(`behaviour.legacy-${method}`, () =>
      lookup(method, value, expected, absent),
    )
  }
  const postgres = postgresRecord(legacy)
  await check('behaviour.legacy-postgres-get', async () =>
    equal(await call('getPostgres', [legacy.pk]), postgres),
  )
  /** @type {[string,unknown,ReturnType<typeof postgresRecord>[],unknown][]} */
  const postgresLookups = [
    ['findPostgresEmail', legacy.email, [postgres], 'absent@example.com'],
    ['findPostgresAge', legacy.age, [postgres, postgresRecord(mutation)], -1],
  ]
  for (const [method, value, expected, absent] of postgresLookups) {
    await check(`behaviour.legacy-${method}`, () =>
      lookup(method, value, expected, absent),
    )
  }
  // Mutation checks are deliberately separate so #1535 can insert no-rewrite here.
  return {
    checks,
    async mutate() {
      await check('behaviour.fresh-write', async () => {
        equal(await call('get', [fresh.pk]), null)
        await call('put', [fresh])
        const actual = await call('get', [fresh.pk])
        if (!isDeepStrictEqual(actual, fresh))
          equal(actual, {
            ...fresh,
            emailLower: fresh.emailLower.toLowerCase(),
          })
      })
      await check('behaviour.downcase-new-write-lookup', async () => {
        await lookup(
          'findEmailLower',
          fresh.emailLower.toLowerCase(),
          [fresh],
          'absent@example.com',
        )
      })
      /** @type {[string,unknown,Customer[],unknown][]} */
      const freshLookups = [
        ['findEmail', fresh.email, [fresh], 'absent@example.com'],
        ['findAge', fresh.age, [legacy, mutation, fresh], -1],
        ['findBalance', fresh.balance, [mutation, fresh], '123456789'],
        ['findActive', fresh.active, [legacy, mutation, fresh], false],
      ]
      for (const [method, value, expected, absent] of freshLookups) {
        await check(`behaviour.fresh-${method}`, () =>
          lookup(method, value, expected, absent),
        )
      }
      await check('behaviour.balance-decimal-string', async () =>
        equal(record(await call('get', [fresh.pk])).balance, fresh.balance),
      )
      // Inspect the stored shape before any read: a `get` that repairs a stale
      // active__hmac would otherwise hide it from migration.active-hmac-absent.
      // Inspection failures abort the Oracle rather than fail this check.
      /** @type {unknown[]} */
      const inspectionFailure = []
      await check('behaviour.set-active', async () => {
        try {
          await call('setActive', [mutation.pk, false])
        } finally {
          try {
            await afterSetActive()
          } catch (error) {
            inspectionFailure.push(error)
          }
        }
        if (inspectionFailure.length) return
        equal(record(await call('get', [mutation.pk])).active, false)
      })
      if (inspectionFailure.length) throw inspectionFailure[0]
      const copiedMutation = {
        ...mutation,
        active: false,
        email: 'Copied@example.com',
        notes: 'updated before copying',
      }
      await check('behaviour.copy-postgres', async () => {
        await call('put', [copiedMutation])
        await call('copyToPostgres', [mutation.pk])
        equal(
          await call('getPostgres', [mutation.pk]),
          postgresRecord(copiedMutation),
        )
      })
      await check('behaviour.copy-dynamo', async () => {
        await call('put', [
          {
            ...mutation,
            active: false,
            email: 'Stale@example.com',
            notes: 'stale destination',
          },
        ])
        await call('copyToDynamo', [mutation.pk])
        const restored = record(await call('get', [mutation.pk]))
        equal(restored.email, 'Copied@example.com')
        equal(restored.notes, 'updated before copying')
      })
      return checks
    },
  }
}
