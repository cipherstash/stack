import { csColumn, csTable, protect } from '@cipherstash/protect'
import { protectDynamoDB } from '@cipherstash/protect-dynamodb'
import { createStores } from './stores.mjs'

const customers = csTable('customers', {
  email: csColumn('email').equality(),
  emailLower: csColumn('emailLower').equality([{ kind: 'downcase' }]),
  age: csColumn('age').dataType('number').equality(),
  balance: csColumn('balance').dataType('bigint').equality(),
  active: csColumn('active').dataType('boolean').equality(),
  notes: csColumn('notes'),
})
const postgresColumns = ['email', 'age', 'notes']

function unwrap(result) {
  if (result.failure) throw new Error(result.failure.message)
  return result.data
}

function legacyBalance(value) {
  if (typeof value !== 'string' || !/^-?(0|[1-9]\d*)$/.test(value)) {
    throw new Error('Balance must be a decimal integer string')
  }
  const number = Number(value)
  if (!Number.isSafeInteger(number))
    throw new Error('Legacy balance exceeds the safe integer range')
  return number
}

function publicCustomer(model) {
  if ('balance' in model) return { ...model, balance: String(model.balance) }
  return model
}

async function legacyClient(env) {
  for (const key of [
    'CS_WORKSPACE_CRN',
    'CS_CLIENT_ID',
    'CS_CLIENT_KEY',
    'CS_CLIENT_ACCESS_KEY',
  ]) {
    if (!env[key]) throw new Error(`Missing ${key}`)
  }
  const region = env.CS_WORKSPACE_CRN.split(':')[1]
  const saved = {
    CS_CTS_HOST: process.env.CS_CTS_HOST,
    CS_ZEROKMS_HOST: process.env.CS_ZEROKMS_HOST,
  }
  process.env.CS_CTS_HOST =
    env.CS_CTS_HOST ?? `https://${region}.cts.cipherstashmanaged.net`
  process.env.CS_ZEROKMS_HOST =
    env.CS_ZEROKMS_HOST ?? `https://${region}.viturhosted.net`
  try {
    return await protect({
      schemas: [customers],
      workspaceCrn: env.CS_WORKSPACE_CRN,
      clientId: env.CS_CLIENT_ID,
      clientKey: env.CS_CLIENT_KEY,
      accessKey: env.CS_CLIENT_ACCESS_KEY,
    })
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

export async function createApp(env = process.env) {
  const client = await legacyClient(env)
  const encrypted = protectDynamoDB({ protectClient: client })
  const stores = await createStores(env)

  async function decrypt(item) {
    return item === null
      ? null
      : publicCustomer(unwrap(await encrypted.decryptModel(item, customers)))
  }

  async function term(column, value) {
    const [hmac] = unwrap(
      await encrypted.createSearchTerms([
        { value, column: customers[column], table: customers },
      ]),
    )
    return hmac
  }

  async function find(column, value) {
    const items = await stores.query(column, await term(column, value))
    return Promise.all(items.map(decrypt))
  }

  function fromPostgres(row) {
    if (row === null) return null
    return Object.assign(
      { pk: row.pk },
      ...postgresColumns.map((column) => ({
        [`${column}__source`]: row[column].c,
        ...(typeof row[column].hm === 'string'
          ? { [`${column}__hmac`]: row[column].hm }
          : {}),
      })),
    )
  }

  async function findPostgres(column, value) {
    const rows = await stores.findPostgres(column, {
      v: 3,
      i: { t: 'customers', c: column },
      hm: await term(column, value),
    })
    return Promise.all(rows.map((row) => decrypt(fromPostgres(row))))
  }

  return {
    async put(customer) {
      const item = unwrap(
        await encrypted.encryptModel(
          { ...customer, balance: legacyBalance(customer.balance) },
          customers,
        ),
      )
      await stores.put(item)
    },
    async get(pk) {
      return decrypt(await stores.get(pk))
    },
    findEmail: (value) => find('email', value),
    findEmailLower: (value) => find('emailLower', value),
    findAge: (value) => find('age', value),
    findBalance: (value) => find('balance', legacyBalance(value)),
    findActive: (value) => find('active', value),
    async setActive(pk, active) {
      const attributes = unwrap(
        await encrypted.encryptModel({ active }, customers),
      )
      await stores.updateActive(pk, attributes)
    },
    async copyToPostgres(pk) {
      const item = await stores.get(pk)
      if (!item) throw new Error('Customer not found')
      const row = Object.fromEntries(
        postgresColumns.map((column) => [
          column,
          {
            v: 3,
            i: { t: 'customers', c: column },
            c: item[`${column}__source`],
            ...(typeof item[`${column}__hmac`] === 'string'
              ? { hm: item[`${column}__hmac`] }
              : {}),
          },
        ]),
      )
      await stores.putPostgres({ pk, ...row })
    },
    async getPostgres(pk) {
      return decrypt(fromPostgres(await stores.getPostgres(pk)))
    },
    findPostgresEmail: (value) => findPostgres('email', value),
    findPostgresAge: (value) => findPostgres('age', value),
    async copyToDynamo(pk) {
      const row = await stores.getPostgres(pk)
      if (!row) throw new Error('Customer not found')
      const existing = await stores.get(pk)
      await stores.put({ ...existing, ...fromPostgres(row) })
    },
    close: () => stores.close(),
  }
}
