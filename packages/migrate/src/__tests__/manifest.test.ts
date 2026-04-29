import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { manifestPath, readManifest, writeManifest } from '../manifest.js'

describe('manifest', () => {
  it('returns null when manifest is absent', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      const result = await readManifest(tmp)
      expect(result).toBeNull()
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('round-trips a manifest through write and read', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      await writeManifest(
        {
          version: 1,
          tables: {
            users: [
              {
                column: 'email',
                castAs: 'text',
                indexes: ['unique', 'match'],
                targetPhase: 'cut-over',
                pkColumn: 'id',
              },
            ],
          },
        },
        tmp,
      )
      const read = await readManifest(tmp)
      expect(read?.tables.users?.[0]?.column).toBe('email')
      expect(read?.tables.users?.[0]?.indexes).toEqual(['unique', 'match'])
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('applies defaults for optional fields', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      await writeManifest(
        {
          version: 1,
          tables: {
            users: [
              {
                column: 'email',
                castAs: 'text',
                indexes: [],
                targetPhase: 'cut-over',
              },
            ],
          },
        },
        tmp,
      )
      const read = await readManifest(tmp)
      expect(read?.tables.users?.[0]?.targetPhase).toBe('cut-over')
      expect(read?.tables.users?.[0]?.indexes).toEqual([])
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('rejects invalid index kinds', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      await expect(
        writeManifest(
          {
            version: 1,
            tables: {
              users: [
                {
                  column: 'email',
                  castAs: 'text',
                  // biome-ignore lint/suspicious/noExplicitAny: intentional bad input
                  indexes: ['bogus' as any],
                  targetPhase: 'cut-over',
                },
              ],
            },
          },
          tmp,
        ),
      ).rejects.toThrow()
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('exposes the canonical path', () => {
    const result = manifestPath('/tmp/project')
    expect(result).toBe('/tmp/project/.cipherstash/migrations.json')
  })
})
