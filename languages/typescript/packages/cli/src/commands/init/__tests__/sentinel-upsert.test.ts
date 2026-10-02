import { describe, expect, it } from 'vitest'
import {
  SENTINEL_END,
  SENTINEL_START,
  upsertManagedBlock,
} from '../lib/sentinel-upsert.js'

describe('upsertManagedBlock', () => {
  const managed = 'rule one\nrule two'

  it('creates a wrapped block when file is missing', () => {
    const result = upsertManagedBlock({ managed })
    expect(result).toContain(SENTINEL_START)
    expect(result).toContain(SENTINEL_END)
    expect(result).toContain('rule one')
    expect(result).toContain('rule two')
  })

  it('replaces only the managed region on re-run', () => {
    const initial = upsertManagedBlock({ managed: 'old rule' })
    const wrapped = `# user header\n\n${initial}\n# user footer\n`

    const next = upsertManagedBlock({ existing: wrapped, managed: 'new rule' })
    expect(next).toContain('# user header')
    expect(next).toContain('# user footer')
    expect(next).toContain('new rule')
    expect(next).not.toContain('old rule')
  })

  it('appends managed block when sentinels absent', () => {
    const existing = '# pre-existing CLAUDE.md content\n'
    const result = upsertManagedBlock({ existing, managed })
    expect(result.startsWith('# pre-existing CLAUDE.md content')).toBe(true)
    expect(result).toContain(SENTINEL_START)
  })

  it('throws on a malformed sentinel pair', () => {
    const broken = `${SENTINEL_END}\nstuff\n${SENTINEL_START}\n`
    expect(() => upsertManagedBlock({ existing: broken, managed })).toThrow(
      /malformed/i,
    )
  })

  it('throws when only one sentinel is present', () => {
    const orphan = `intro\n${SENTINEL_START}\nstuff\n`
    expect(() => upsertManagedBlock({ existing: orphan, managed })).toThrow(
      /malformed/i,
    )
  })
})
