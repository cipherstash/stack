import {
  CreateTableCommand,
  DescribeTableCommand,
  DynamoDBClient,
  waitUntilTableExists,
} from '@aws-sdk/client-dynamodb'
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  ScanCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb'
import postgres from 'postgres'

export async function createStores(env = process.env) {
  for (const key of ['HARNESS_DYNAMO_URL', 'HARNESS_TABLE', 'DATABASE_URL']) {
    if (!env[key]) throw new Error(`Missing ${key}`)
  }
  const endpoint = new URL(env.HARNESS_DYNAMO_URL)
  const database = new URL(env.DATABASE_URL)
  if (
    ![endpoint, database].every((url) =>
      ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname),
    )
  ) {
    throw new Error('Fixture stores must be local disposable databases')
  }
  const raw = new DynamoDBClient({
    endpoint: endpoint.href,
    region: 'us-east-1',
    credentials: {
      accessKeyId: 'migrationfixture',
      secretAccessKey: 'migrationfixture',
    },
  })
  const dynamo = DynamoDBDocumentClient.from(raw)
  const TableName = env.HARNESS_TABLE
  const sql = postgres(env.DATABASE_URL, { prepare: false, onnotice: () => {} })

  async function pages(Command, input) {
    const items = []
    let cursor
    do {
      const page = await dynamo.send(
        new Command({
          TableName,
          Limit: 2,
          ...input,
          ...(cursor ? { ExclusiveStartKey: cursor } : {}),
        }),
      )
      items.push(...(page.Items ?? []))
      cursor = page.LastEvaluatedKey
    } while (cursor)
    return items.sort((a, b) => a.pk.localeCompare(b.pk))
  }

  async function scan() {
    return pages(ScanCommand, { ConsistentRead: true })
  }

  return {
    async init() {
      try {
        await raw.send(new DescribeTableCommand({ TableName }))
      } catch (error) {
        if (error.name !== 'ResourceNotFoundException') throw error
        await raw.send(
          new CreateTableCommand({
            TableName,
            BillingMode: 'PAY_PER_REQUEST',
            AttributeDefinitions: [
              { AttributeName: 'pk', AttributeType: 'S' },
              { AttributeName: 'email__hmac', AttributeType: 'S' },
            ],
            KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }],
            GlobalSecondaryIndexes: [
              {
                IndexName: 'email-index',
                KeySchema: [{ AttributeName: 'email__hmac', KeyType: 'HASH' }],
                Projection: { ProjectionType: 'ALL' },
              },
            ],
          }),
        )
      }
      await waitUntilTableExists(
        { client: raw, maxWaitTime: 60 },
        { TableName },
      )
      await sql`CREATE TABLE IF NOT EXISTS customers (
        pk text PRIMARY KEY,
        email public.eql_v3_text_eq,
        age public.eql_v3_integer_eq,
        notes public.eql_v3_text
      )`
    },
    async put(item) {
      await dynamo.send(new PutCommand({ TableName, Item: item }))
    },
    async get(pk) {
      const result = await dynamo.send(
        new GetCommand({ TableName, Key: { pk }, ConsistentRead: true }),
      )
      return result.Item ?? null
    },
    scan,
    async query(column, hmac) {
      if (
        !['email', 'emailLower', 'age', 'balance', 'active'].includes(column)
      ) {
        throw new Error('Unsupported lookup column')
      }
      const expression = {
        ExpressionAttributeNames: { '#term': `${column}__hmac` },
        ExpressionAttributeValues: { ':term': hmac },
      }
      return column === 'email'
        ? pages(QueryCommand, {
            ...expression,
            IndexName: 'email-index',
            KeyConditionExpression: '#term = :term',
          })
        : pages(ScanCommand, {
            ...expression,
            ConsistentRead: true,
            FilterExpression: '#term = :term',
          })
    },
    async updateActive(pk, attributes) {
      await dynamo.send(
        new UpdateCommand({
          TableName,
          Key: { pk },
          ConditionExpression: 'attribute_exists(pk)',
          UpdateExpression:
            'SET active__source = :source, active__hmac = :hmac',
          ExpressionAttributeValues: {
            ':source': attributes.active__source,
            ':hmac': attributes.active__hmac,
          },
        }),
      )
    },
    async putPostgres(row) {
      await sql`INSERT INTO customers (pk, email, age, notes)
        VALUES (${row.pk}, ${sql.json(row.email)}::jsonb, ${sql.json(row.age)}::jsonb, ${sql.json(row.notes)}::jsonb)
        ON CONFLICT (pk) DO UPDATE SET email = excluded.email, age = excluded.age, notes = excluded.notes`
    },
    async getPostgres(pk) {
      const rows =
        await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes
        FROM customers WHERE pk = ${pk}`
      return rows[0] ?? null
    },
    async findPostgres(column, term) {
      if (column === 'email') {
        return sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes
          FROM customers WHERE eql_v3.eq(email, ${sql.json(term)}::jsonb::eql_v3.query_text_eq) ORDER BY pk`
      }
      if (column === 'age') {
        return sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes
          FROM customers WHERE eql_v3.eq(age, ${sql.json(term)}::jsonb::eql_v3.query_integer_eq) ORDER BY pk`
      }
      throw new Error('Unsupported Postgres lookup column')
    },
    async clear() {
      for (const item of await scan()) {
        await dynamo.send(
          new DeleteCommand({ TableName, Key: { pk: item.pk } }),
        )
      }
      await sql`DELETE FROM customers`
    },
    async close() {
      raw.destroy()
      await sql.end()
    },
  }
}
