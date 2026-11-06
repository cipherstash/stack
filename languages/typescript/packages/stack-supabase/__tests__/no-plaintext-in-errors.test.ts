import { logger } from '@cipherstash/stack/adapter-kit'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { EncryptedQueryBuilderImpl } from '../src/query-builder'
import {
  createMockEncryptionClient,
  createMockSupabase,
} from './helpers/supabase-mock'

// A search term on an encrypted column is plaintext the caller chose to
// protect. The library promises never to log plaintext, and its own error
// messages are routinely logged by callers, so neither may carry the term.
// These tests use distinctive sentinels so a substring check cannot pass by
// accident against an ordinary English word in the message.

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  nickname: types.TextEq('nickname'),
})
const COLUMNS = ['id', 'email', 'nickname']

function builder(encryptionClient = createMockEncryptionClient()) {
  const supabase = createMockSupabase([])
  return new EncryptedQueryBuilderImpl(
    'users',
    users,
    encryptionClient,
    supabase.client,
    COLUMNS,
  )
}

/** Every string the logger was handed, across all levels. */
function logged(spies: ReturnType<typeof vi.spyOn>[]): string {
  return spies
    .flatMap((spy) => spy.mock.calls.flat())
    .map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg)))
    .join('\n')
}

function spyLogger() {
  return (['error', 'warn', 'info', 'debug'] as const).map((level) =>
    vi.spyOn(logger, level).mockImplementation(() => {}),
  )
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('plaintext search terms stay out of errors and logs', () => {
  it('a too-short matches() needle is neither logged nor echoed in the error', async () => {
    const spies = spyLogger()

    const { error } = await builder().select('id').matches('email', 'Qz')

    expect(error?.message).toMatch(/at least 3 characters/)
    expect(error?.message).not.toContain('Qz')
    expect(logged(spies)).not.toContain('Qz')
  })

  it('a like() pattern with unsupported wildcards is not echoed in the error', () => {
    for (const pattern of ['Qzx%wvy', 'Qzx_wvy']) {
      let message = ''
      try {
        builder().select('id').like('email', pattern)
      } catch (err) {
        message = (err as Error).message
      }
      expect(message, pattern).toMatch(/cannot honor/)
      expect(message, pattern).not.toContain('Qzx')
      expect(message, pattern).not.toContain('wvy')
    }
  })

  // The catch around query execution sees errors from every layer (encryption,
  // PostgREST, the network), and any of them may quote a value. It reports the
  // failure's kind; the message itself goes back to the caller, not to the log.
  it('a failed query logs the failure kind, not the error message', async () => {
    const encryption = createMockEncryptionClient()
    vi.spyOn(
      encryption as unknown as { bulkEncrypt: (...a: unknown[]) => unknown },
      'bulkEncrypt',
    ).mockImplementation(() => {
      throw new TypeError('value "Qzx-secret-wvy" could not be encoded')
    })
    const spies = spyLogger()

    const { error } = await builder(encryption)
      .select('id')
      .in('nickname', ['Qzx-secret-wvy', 'other'])

    expect(error?.message).toContain('Qzx-secret-wvy')
    const output = logged(spies)
    expect(output).toMatch(/failed on table "users"/)
    expect(output).toContain('TypeError')
    expect(output).not.toContain('Qzx')
  })
})
