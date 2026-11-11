import { createCheck, equal, safePostgresCause } from './behaviour-checks.mjs'

export const postgresLegacy = [
  { pk: 'ada', email: 'ada@example.com', age: 36, notes: 'engines' },
  { pk: 'alan', email: 'alan@example.com', age: 36, notes: 'machines' },
  { pk: 'grace', email: 'grace@example.com', age: 85, notes: 'compilers' },
]
const fresh = {
  pk: 'new',
  email: 'new@example.com',
  age: 36,
  notes: 'written by Stack',
}

/** Calls only the application API through the restricted App Host. The driver
 * inspects retained bytes between this read-only phase and mutate().
 * @param {(method:string,args:unknown[])=>Promise<unknown>} call
 * @param {()=>Promise<void>} afterPut */
export async function postgresBehaviour(call, afterPut = async () => {}) {
  /** @type {import('../types.js').OracleCheck[]} */
  const checks = []
  const check = createCheck(checks, safePostgresCause)
  await check('behaviour.postgres-legacy-read', async () => {
    for (const row of postgresLegacy) equal(await call('get', [row.pk]), row)
  })
  await check('behaviour.postgres-email-lookup', async () => {
    equal(await call('findEmail', [postgresLegacy[0].email]), [
      postgresLegacy[0],
    ])
    equal(await call('findEmail', ['absent@example.com']), [])
  })
  await check('behaviour.postgres-age-lookup', async () => {
    equal(await call('findAge', [36]), postgresLegacy.slice(0, 2))
    equal(await call('findAge', [85]), [postgresLegacy[2]])
    equal(await call('findAge', [-1]), [])
  })
  return {
    checks,
    async mutate() {
      await check('behaviour.postgres-fresh-write', async () => {
        equal(await call('get', [fresh.pk]), null)
        await call('put', [fresh])
        await afterPut()
        equal(await call('get', [fresh.pk]), fresh)
      })
      await check('behaviour.postgres-fresh-lookups', async () => {
        equal(await call('findEmail', [fresh.email]), [fresh])
        equal(await call('findAge', [fresh.age]), [
          ...postgresLegacy.slice(0, 2),
          fresh,
        ])
      })
      return checks
    },
  }
}
