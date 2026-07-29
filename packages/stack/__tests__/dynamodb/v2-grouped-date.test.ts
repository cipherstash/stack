/**
 * A legacy grouped v2 field is stored as `<group>.<leaf>__source` while the v2
 * schema knew it only as `<leaf>`, so the read path's bare-leaf fallback matches
 * it against the registered column `placedAt` and writes the rebuilt envelope
 * back at `details.placedAt`.
 *
 * Both clients resolve their date columns from the REGISTERED paths — native via
 * `rowReconstructor` (`encryption/client-v3.ts`), WASM via `dateFields`
 * (`wasm-inline.ts`) — so neither reconstructs `details.placedAt` and the value
 * came back as an ISO string. The adapter is the only layer that knows the alias
 * happened, so it reconstructs there, which covers both entries at once.
 *
 * The stubs below return plaintext rather than recording calls: the defect is in
 * the value handed back to the caller, so only asserting on the returned row can
 * catch it.
 */
import { describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { encryptedTable, types } from '@/eql/v3'

const orders = encryptedTable('orders', {
  placedAt: types.DateEq('placed_at'),
  reference: types.TextEq('reference'),
})

const ISO = '2024-01-01T00:00:00.000Z'

/** A client whose decrypt returns a fixed plaintext row, ignoring its input. */
function returningClient(rows: Record<string, unknown>[]) {
  return {
    getEncryptConfig: () => ({ tables: { orders: {} } }),
    encryptModel: () => Promise.resolve({ data: {} }),
    bulkEncryptModels: () => Promise.resolve({ data: [] }),
    decryptModel: () => Promise.resolve({ data: rows[0] }),
    bulkDecryptModels: () => Promise.resolve({ data: rows }),
  } as never
}

const groupedItem = (leaf: string) => ({
  pk: 'order#1',
  details: { [`${leaf}__source`]: 'BASE64CT', [`${leaf}__hmac`]: 'HMAC' },
})

describe('legacy grouped v2 date reconstruction', () => {
  it('reconstructs a Date at the nested path a bare-leaf match landed at', async () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: returningClient([
        { pk: 'order#1', details: { placedAt: ISO } },
      ]),
    })

    const result = await dynamo.decryptModel(groupedItem('placedAt'), orders, {
      storedEqlVersion: 2,
    })

    expect(result.failure).toBeUndefined()
    const details = (result.data as { details: { placedAt: unknown } }).details
    expect(details.placedAt).toBeInstanceOf(Date)
    expect((details.placedAt as Date).toISOString()).toBe(ISO)
  })

  it('reconstructs on the bulk path, per item', async () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: returningClient([
        { pk: 'order#1', details: { placedAt: ISO } },
        { pk: 'order#2', details: { placedAt: '2025-06-15T12:30:00.000Z' } },
      ]),
    })

    const result = await dynamo.bulkDecryptModels(
      [groupedItem('placedAt'), groupedItem('placedAt')],
      orders,
      { storedEqlVersion: 2 },
    )

    expect(result.failure).toBeUndefined()
    const rows = result.data as { details: { placedAt: unknown } }[]
    expect(rows[0]?.details.placedAt).toBeInstanceOf(Date)
    expect(rows[1]?.details.placedAt).toBeInstanceOf(Date)
  })

  /**
   * Items in one bulk call are heterogeneous: `details.placedAt` is an encrypted
   * date column in the first item and an ordinary plaintext attribute in the
   * second. Collecting aliased paths into one shared set would convert the
   * second item's string too, so the paths are collected per item.
   */
  it('does not carry one item aliased paths onto another', async () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: returningClient([
        { pk: 'order#1', details: { placedAt: ISO } },
        { pk: 'order#2', details: { placedAt: ISO } },
      ]),
    })

    const result = await dynamo.bulkDecryptModels(
      [groupedItem('placedAt'), { pk: 'order#2', details: { placedAt: ISO } }],
      orders,
      { storedEqlVersion: 2 },
    )

    const rows = result.data as { details: { placedAt: unknown } }[]
    expect(rows[0]?.details.placedAt).toBeInstanceOf(Date)
    expect(rows[1]?.details.placedAt).toBe(ISO)
  })

  it('leaves a bare-leaf-matched text column as a string', async () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: returningClient([
        { pk: 'order#1', details: { reference: ISO } },
      ]),
    })

    const result = await dynamo.decryptModel(groupedItem('reference'), orders, {
      storedEqlVersion: 2,
    })

    expect(
      (result.data as { details: { reference: unknown } }).details.reference,
    ).toBe(ISO)
  })

  it('leaves unrelated plaintext attributes untouched', async () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: returningClient([
        {
          pk: 'order#1',
          note: ISO,
          details: { placedAt: ISO, memo: ISO },
        },
      ]),
    })

    const result = await dynamo.decryptModel(groupedItem('placedAt'), orders, {
      storedEqlVersion: 2,
    })

    const data = result.data as {
      note: unknown
      details: { placedAt: unknown; memo: unknown }
    }
    expect(data.note).toBe(ISO)
    expect(data.details.memo).toBe(ISO)
    expect(data.details.placedAt).toBeInstanceOf(Date)
  })

  it('does not reconstruct on a stored v3 read, where the fallback never fires', async () => {
    const dynamo = encryptedDynamoDB({
      encryptionClient: returningClient([
        { pk: 'order#1', details: { placedAt: ISO } },
      ]),
    })

    const result = await dynamo.decryptModel(groupedItem('placedAt'), orders)

    expect(
      (result.data as { details: { placedAt: unknown } }).details.placedAt,
    ).toBe(ISO)
  })
})
