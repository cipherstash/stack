import { isDeepStrictEqual } from 'node:util'

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
/** Calls only the App Host JSON RPC boundary; never imports application code.
 * @param {AppCall} call
 * @param {()=>Promise<void>} afterSetActive */
export async function behaviour(call, afterSetActive = async () => {}) {
  /** @type {import('../types.js').OracleCheck[]} */
  const checks = []
  /** @param {string} id @param {()=>Promise<unknown>} action */
  async function check(id, action) {
    try {
      await action()
      checks.push({ id, passed: true })
    } catch (error) {
      checks.push({
        id,
        passed: false,
        cause: error instanceof Error ? error.message : String(error),
      })
    }
  }
  /** @param {unknown} actual @param {unknown} expected */
  function equal(actual, expected) {
    if (!isDeepStrictEqual(actual, expected))
      throw new Error('Unexpected application result')
  }
  await check('behaviour.legacy-get', async () =>
    equal(await call('get', [legacy.pk]), legacy),
  )
  /** @type {[string,unknown][]} */
  const legacyLookups = [
    ['findEmail', legacy.email],
    ['findEmailLower', legacy.emailLower.toLowerCase()],
    ['findAge', legacy.age],
    ['findBalance', legacy.balance],
    ['findActive', legacy.active],
  ]
  for (const [method, value] of legacyLookups) {
    await check(`behaviour.legacy-${method}`, async () => {
      const found = records(await call(method, [value]))
      if (!found.some((record) => isDeepStrictEqual(record, legacy)))
        throw Error('Legacy Data not found')
    })
  }
  const postgres = postgresRecord(legacy)
  await check('behaviour.legacy-postgres-get', async () =>
    equal(await call('getPostgres', [legacy.pk]), postgres),
  )
  /** @type {[string,unknown][]} */
  const postgresLookups = [
    ['findPostgresEmail', legacy.email],
    ['findPostgresAge', legacy.age],
  ]
  for (const [method, value] of postgresLookups) {
    await check(`behaviour.legacy-${method}`, async () => {
      if (
        !records(await call(method, [value])).some((record) =>
          isDeepStrictEqual(record, postgres),
        )
      )
        throw Error('Legacy Postgres Data not found')
    })
  }
  // Mutation checks are deliberately separate so #1535 can insert no-rewrite here.
  return {
    checks,
    async mutate() {
      await check('behaviour.fresh-write', async () => {
        equal(await call('get', [fresh.pk]), null)
        await call('put', [fresh])
        const actual = record(await call('get', [fresh.pk]))
        equal(
          { ...actual, emailLower: String(actual.emailLower).toLowerCase() },
          { ...fresh, emailLower: fresh.emailLower.toLowerCase() },
        )
      })
      await check('behaviour.downcase-new-write-lookup', async () => {
        if (
          !records(
            await call('findEmailLower', [fresh.emailLower.toLowerCase()]),
          ).some((item) => record(item).pk === fresh.pk)
        )
          throw Error('New downcase write not found')
      })
      /** @type {[string,unknown][]} */
      const freshLookups = [
        ['findEmail', fresh.email],
        ['findAge', fresh.age],
        ['findBalance', fresh.balance],
        ['findActive', fresh.active],
      ]
      for (const [method, value] of freshLookups) {
        await check(`behaviour.fresh-${method}`, async () => {
          if (
            !records(await call(method, [value])).some(
              (item) => record(item).pk === fresh.pk,
            )
          )
            throw Error('Fresh write not found')
        })
      }
      await check('behaviour.balance-decimal-string', async () =>
        equal(record(await call('get', [fresh.pk])).balance, fresh.balance),
      )
      await check('behaviour.set-active', async () => {
        await call('setActive', [mutation.pk, false])
        equal(record(await call('get', [mutation.pk])).active, false)
      })
      await afterSetActive()
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
