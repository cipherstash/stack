import { encryptedDynamoDB } from '@cipherstash/stack/dynamodb'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import { createStores } from './stores.mjs'

const customers = encryptedTable('customers', {
  email: types.TextEq('email'),
  emailLower: types.TextEq('emailLower'),
  age: types.IntegerEq('age'),
  balance: types.BigintEq('balance'),
  active: types.Boolean('active'),
  notes: types.Text('notes'),
})
const postgresColumns = ['email', 'age', 'notes']
function unwrap(result) {
  if (result.failure) throw Error(result.failure.message)
  return result.data
}
function publicCustomer(model) {
  return 'balance' in model
    ? { ...model, balance: String(model.balance) }
    : model
}
function balance(value) {
  if (
    typeof value !== 'string' ||
    !/^-?(0|[1-9]\d*)$/.test(value) ||
    !Number.isSafeInteger(Number(value))
  )
    throw Error('Balance must be a safe decimal integer string')
  return BigInt(value)
}
export async function createApp(env = process.env) {
  const client = await Encryption({ schemas: [customers] })
  const encrypted = encryptedDynamoDB({ encryptionClient: client })
  const stores = await createStores(env)
  async function decrypt(item) {
    return item === null
      ? null
      : publicCustomer(unwrap(await encrypted.decryptModel(item, customers)))
  }
  async function term(column, value) {
    const result = unwrap(
      await client.encryptQuery(value, {
        table: customers,
        column: customers[column],
      }),
    )
    if (!result || typeof result !== 'object' || typeof result.hm !== 'string')
      throw Error('Missing equality term')
    return result.hm
  }
  async function find(column, value) {
    return Promise.all(
      (await stores.query(column, await term(column, value))).map(decrypt),
    )
  }
  function fromPostgres(row) {
    return row === null
      ? null
      : Object.assign(
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
      await stores.put(
        unwrap(
          await encrypted.encryptModel(
            {
              ...customer,
              emailLower: customer.emailLower.toLowerCase(),
              balance: balance(customer.balance),
            },
            customers,
          ),
        ),
      )
    },
    get: async (pk) => decrypt(await stores.get(pk)),
    findEmail: (value) => find('email', value),
    findEmailLower: (value) => find('emailLower', value.toLowerCase()),
    findAge: (value) => find('age', value),
    findBalance: (value) => find('balance', balance(value)),
    async findActive(value) {
      return (await Promise.all((await stores.scan()).map(decrypt))).filter(
        (item) => item.active === value,
      )
    },
    async setActive(pk, active) {
      await stores.updateActive(
        pk,
        unwrap(await encrypted.encryptModel({ active }, customers)),
      )
    },
    async copyToPostgres(pk) {
      const item = await stores.get(pk)
      if (!item) throw Error('Customer not found')
      await stores.putPostgres({
        pk,
        ...Object.fromEntries(
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
        ),
      })
    },
    getPostgres: async (pk) =>
      decrypt(fromPostgres(await stores.getPostgres(pk))),
    findPostgresEmail: (value) => findPostgres('email', value),
    findPostgresAge: (value) => findPostgres('age', value),
    async copyToDynamo(pk) {
      const row = await stores.getPostgres(pk)
      if (!row) throw Error('Customer not found')
      await stores.put({ ...(await stores.get(pk)), ...fromPostgres(row) })
    },
    close: () => stores.close(),
  }
}
