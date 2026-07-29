import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  manifestPath,
  readManifest,
  setManifestTargetPhase,
  upsertManifestColumn,
  writeManifest,
} from '../manifest.js'

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

  it('retains legacy v2 status fields for existing migration history', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      const legacy = {
        version: 1,
        tables: {
          users: [
            {
              column: 'email',
              castAs: 'text',
              indexes: ['unique'],
              targetPhase: 'cut-over',
              encryptedColumn: 'email_encrypted',
              eqlVersion: 2,
            },
          ],
        },
      }
      const file = manifestPath(tmp)
      mkdirSync(join(tmp, '.cipherstash'), { recursive: true })
      writeFileSync(file, JSON.stringify(legacy), 'utf-8')

      expect(await readManifest(tmp)).toMatchObject({
        tables: {
          users: [
            {
              targetPhase: 'cut-over',
              encryptedColumn: 'email_encrypted',
              eqlVersion: 2,
            },
          ],
        },
      })
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

describe('upsertManifestColumn', () => {
  it('creates the manifest if it does not exist', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      await upsertManifestColumn(
        'users',
        {
          column: 'email',
          castAs: 'text',
          indexes: ['unique', 'match'],
          targetPhase: 'cut-over',
        },
        tmp,
      )
      const read = await readManifest(tmp)
      expect(read?.tables.users).toHaveLength(1)
      expect(read?.tables.users?.[0]?.column).toBe('email')
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('replaces an existing entry for the same column', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      await upsertManifestColumn(
        'users',
        {
          column: 'email',
          castAs: 'text',
          indexes: ['unique'],
          targetPhase: 'cut-over',
        },
        tmp,
      )
      await upsertManifestColumn(
        'users',
        {
          column: 'email',
          castAs: 'text',
          indexes: ['unique', 'match'],
          targetPhase: 'cut-over',
        },
        tmp,
      )
      const read = await readManifest(tmp)
      expect(read?.tables.users).toHaveLength(1)
      expect(read?.tables.users?.[0]?.indexes).toEqual(['unique', 'match'])
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('preserves entries for other columns in the same table', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      await upsertManifestColumn(
        'users',
        {
          column: 'email',
          castAs: 'text',
          indexes: ['unique'],
          targetPhase: 'cut-over',
        },
        tmp,
      )
      await upsertManifestColumn(
        'users',
        {
          column: 'phone',
          castAs: 'text',
          indexes: ['unique'],
          targetPhase: 'cut-over',
        },
        tmp,
      )
      const read = await readManifest(tmp)
      expect(read?.tables.users).toHaveLength(2)
      expect(read?.tables.users?.map((c) => c.column).sort()).toEqual([
        'email',
        'phone',
      ])
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })
})

describe('setManifestTargetPhase', () => {
  it('updates targetPhase for an existing column', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      await upsertManifestColumn(
        'users',
        {
          column: 'email',
          castAs: 'text',
          indexes: ['unique'],
          targetPhase: 'cut-over',
        },
        tmp,
      )
      await setManifestTargetPhase('users', 'email', 'dropped', tmp)
      const read = await readManifest(tmp)
      expect(read?.tables.users?.[0]?.targetPhase).toBe('dropped')
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('is a no-op when the column is not tracked', async () => {
    const tmp = mkdtempSync(join(tmpdir(), 'cs-manifest-'))
    try {
      // No manifest at all — should not throw, should not create.
      await setManifestTargetPhase('users', 'email', 'dropped', tmp)
      expect(await readManifest(tmp)).toBeNull()
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })
})
