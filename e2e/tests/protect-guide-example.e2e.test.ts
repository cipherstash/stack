import { expect, it } from 'vitest'
import { migrateDynamoExample } from '../migration-guide/dynamodb.ts'
import { authConfigured } from './helpers/legacy-protect'

if (!authConfigured)
  throw new Error('protect-guide-example requires all four CS_* credentials')

it('runs the npm DynamoDB example through legacy reads, new writes and boolean updates', async () => {
  expect(await migrateDynamoExample()).toEqual({
    legacyBytesPreserved: true,
    newWritesVerified: true,
    booleanUpdateVerified: true,
  })
}, 120_000)
