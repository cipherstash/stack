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

/** Calls only the App Host JSON RPC boundary; never imports application code. */
export async function behaviour(call) {
  const checks = []
  async function check(id, action) {
    try {
      await action()
      checks.push({ id, passed: true })
    } catch (error) {
      checks.push({ id, passed: false, cause: String(error.message ?? error) })
    }
  }
  function equal(actual, expected) {
    if (!isDeepStrictEqual(actual, expected))
      throw new Error('Unexpected application result')
  }
  await check('behaviour.legacy-get', async () =>
    equal(await call('get', [legacy.pk]), legacy),
  )
  for (const [method, value] of [
    ['findEmail', legacy.email],
    ['findEmailLower', legacy.emailLower.toLowerCase()],
    ['findAge', legacy.age],
    ['findBalance', legacy.balance],
    ['findActive', legacy.active],
  ]) {
    await check(`behaviour.legacy-${method}`, async () => {
      const records = await call(method, [value])
      if (!records.some((record) => isDeepStrictEqual(record, legacy)))
        throw Error('Legacy Data not found')
    })
  }
  const postgres = Object.fromEntries(
    ['pk', 'email', 'age', 'notes'].map((key) => [key, legacy[key]]),
  )
  await check('behaviour.legacy-postgres-get', async () =>
    equal(await call('getPostgres', [legacy.pk]), postgres),
  )
  for (const [method, value] of [
    ['findPostgresEmail', legacy.email],
    ['findPostgresAge', legacy.age],
  ]) {
    await check(`behaviour.legacy-${method}`, async () => {
      if (
        !(await call(method, [value])).some((record) =>
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
        equal(await call('get', [fresh.pk]), {
          ...fresh,
          emailLower: fresh.emailLower.toLowerCase(),
        })
      })
      await check('behaviour.downcase-new-write-lookup', async () => {
        if (
          !(
            await call('findEmailLower', [fresh.emailLower.toLowerCase()])
          ).some((record) => record.pk === fresh.pk)
        )
          throw Error('New downcase write not found')
      })
      for (const [method, value] of [
        ['findEmail', fresh.email],
        ['findAge', fresh.age],
        ['findBalance', fresh.balance],
        ['findActive', fresh.active],
      ]) {
        await check(`behaviour.fresh-${method}`, async () => {
          if (
            !(await call(method, [value])).some(
              (record) => record.pk === fresh.pk,
            )
          )
            throw Error('Fresh write not found')
        })
      }
      await check('behaviour.balance-decimal-string', async () =>
        equal((await call('get', [fresh.pk])).balance, fresh.balance),
      )
      await check('behaviour.set-active', async () => {
        await call('setActive', [mutation.pk, false])
        equal((await call('get', [mutation.pk])).active, false)
      })
      await check('behaviour.copy-postgres', async () => {
        await call('copyToPostgres', [mutation.pk])
        equal(
          await call('getPostgres', [mutation.pk]),
          Object.fromEntries(
            ['pk', 'email', 'age', 'notes'].map((key) => [key, mutation[key]]),
          ),
        )
      })
      await check('behaviour.copy-dynamo', async () => {
        await call('copyToDynamo', [mutation.pk])
        equal((await call('get', [mutation.pk])).email, mutation.email)
      })
      return checks
    },
  }
}
