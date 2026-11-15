import assert from 'node:assert/strict'
import { csColumn, csTable } from '@cipherstash/protect'
import { protectDynamoDB } from '@cipherstash/protect-dynamodb'
import { encryptedDynamoDB } from '@cipherstash/stack/dynamodb'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import { legacyProtect, ok } from './legacy.ts'

/** Executable before/after example; persistence is in memory, not AWS. */
export async function migrateDynamoExample() {
  const before = csTable('customers', {
    email: csColumn('email').equality(),
    emailLower: csColumn('emailLower').equality([{ kind: 'downcase' }]),
    age: csColumn('age').dataType('number').equality(),
    balance: csColumn('balance').dataType('bigint').equality(),
    active: csColumn('active').dataType('boolean').equality(),
    notes: csColumn('notes'),
  })
  const after = encryptedTable('customers', {
    email: types.TextEq('email'),
    emailLower: types.TextEq('emailLower'),
    age: types.IntegerEq('age'),
    balance: types.BigintEq('balance'),
    active: types.Boolean('active'),
    notes: types.Text('notes'),
  })
  const legacy = protectDynamoDB({
    protectClient: await legacyProtect([before]),
  })
  const client = await Encryption({ schemas: [after] })
  const stack = encryptedDynamoDB({ encryptionClient: client })
  const original = {
    pk: 'legacy',
    email: 'ada@example.com',
    emailLower: 'Ada@Example.com',
    age: 36,
    balance: 1000,
    active: true,
    notes: 'engines',
  }
  const item: Record<string, unknown> = ok(
    await legacy.encryptModel(original, before),
    'legacy write',
  )
  const snapshot = structuredClone(item)
  const decrypted = ok(await stack.decryptModel(item, after), 'legacy read')
  assert.deepEqual(decrypted, { ...original, balance: 1000n })
  const query = ok(
    await client.encryptQuery(original.emailLower.toLowerCase(), {
      table: after,
      column: after.emailLower,
    }),
    'normalized query',
  )
  assert.equal(hmac(query), item.emailLower__hmac)
  assert.deepEqual(item, snapshot)

  const fresh = {
    ...original,
    pk: 'new',
    emailLower: original.emailLower.toLowerCase(),
    balance: 1000n,
    active: false,
  }
  const written = ok(await stack.encryptModel(fresh, after), 'Stack write')
  assert.equal(written.emailLower__hmac, item.emailLower__hmac)
  assert.equal('active__hmac' in written, false)
  assert.deepEqual(
    ok(await stack.decryptModel(written, after), 'new read'),
    fresh,
  )
  // A partial UpdateItem must remove the previous boolean term atomically.
  const update = { ...item, active__source: written.active__source }
  Reflect.deleteProperty(update, 'active__hmac')
  assert.equal('active__hmac' in update, false)
  const changed = ok(await stack.decryptModel(update, after), 'updated read')
  assert.equal(changed.active, false)
  // The example's replacement boolean lookup decrypts and filters; production
  // must also handle pagination and the cost of scanning its data.
  assert.equal([decrypted, changed].filter((row) => row.active).length, 1)
  const publicValue = JSON.stringify(changed, (_key, value) =>
    typeof value === 'bigint' ? value.toString() : value,
  )
  assert.equal(JSON.parse(publicValue).balance, '1000')
  return {
    legacyBytesPreserved: true,
    newWritesVerified: true,
    booleanUpdateVerified: true,
  }
}

function hmac(value: unknown): string {
  if (
    typeof value === 'object' &&
    value !== null &&
    'hm' in value &&
    typeof value.hm === 'string'
  )
    return value.hm
  throw new Error('Expected an equality term')
}
