import { beforeEach, describe, expect, it, vi } from 'vitest'

const selectMock = vi.fn()
const multiselectMock = vi.fn()
const confirmMock = vi.fn()
const CANCEL = Symbol('clack.cancel')
vi.mock('@clack/prompts', () => ({
  select: (...a: unknown[]) => selectMock(...a),
  multiselect: (...a: unknown[]) => multiselectMock(...a),
  confirm: (...a: unknown[]) => confirmMock(...a),
  isCancel: (v: unknown) => v === CANCEL,
  log: { info: vi.fn(), success: vi.fn(), error: vi.fn() },
  spinner: () => ({ start: vi.fn(), stop: vi.fn() }),
}))

const queryMock = vi.fn()
vi.mock('pg', () => ({
  default: {
    Client: vi.fn(() => ({
      connect: vi.fn(async () => {}),
      query: queryMock,
      end: vi.fn(async () => {}),
    })),
  },
}))

const { buildSchemasFromDatabase } = await import('../introspect.js')
const { generateClientFromSchemas } = await import('../../utils.js')

describe('build flow (introspect → pick → codegen)', () => {
  beforeEach(() => {
    selectMock.mockReset()
    multiselectMock.mockReset()
    confirmMock.mockReset()
    queryMock.mockResolvedValue({
      rows: [
        { table_name: 'users', column_name: 'email', data_type: 'text', udt_name: 'text' },
        { table_name: 'orders', column_name: 'total', data_type: 'integer', udt_name: 'int4' },
      ],
    })
  })

  it('walks two tables and emits a v3 client with the chosen domains', async () => {
    selectMock
      .mockResolvedValueOnce('users').mockResolvedValueOnce('TextEq') // table 1 + email
      .mockResolvedValueOnce('orders').mockResolvedValueOnce('IntegerOrd') // table 2 + total
    multiselectMock
      .mockResolvedValueOnce(['email'])
      .mockResolvedValueOnce(['total'])
    confirmMock.mockResolvedValueOnce(true) // "encrypt columns in another table?"

    const schemas = await buildSchemasFromDatabase('postgresql://x')
    expect(schemas).toHaveLength(2)

    const out = generateClientFromSchemas('postgresql', schemas!)
    expect(out).toContain("email: types.TextEq('email'),")
    expect(out).toContain("total: types.IntegerOrd('total'),")
    expect(out).not.toMatch(/searchOps|v3DomainFactory/)
  })

  it('stops after the first table when the user declines another', async () => {
    selectMock.mockResolvedValueOnce('users').mockResolvedValueOnce('TextEq')
    multiselectMock.mockResolvedValueOnce(['email'])
    confirmMock.mockResolvedValueOnce(false) // decline "another table?"

    const schemas = await buildSchemasFromDatabase('postgresql://x')
    expect(schemas).toEqual([
      { tableName: 'users', columns: [{ name: 'email', domain: 'TextEq' }] },
    ])
  })

  it('returns undefined for an empty public schema', async () => {
    queryMock.mockResolvedValueOnce({ rows: [] })
    expect(await buildSchemasFromDatabase('postgresql://x')).toBeUndefined()
  })
})
