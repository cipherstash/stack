import { expect, test, vi } from 'vitest'
import { snapshotPostgres } from '../run/real-stores.mjs'

test('snapshots project encrypted domains as JSONB before and after conversion', async () => {
  for (const migrated of [false, true]) {
    const names = [
      'email',
      'age',
      'notes',
      ...(migrated ? ['email_v3', 'age_v3', 'notes_v3'] : []),
    ]
    const row = Object.fromEntries([
      ['pk', 'ada'],
      ...names.map((name) => [name, { c: name }]),
    ])
    const query = vi.fn(async (strings: TemplateStringsArray) => {
      if (strings.join('').includes('pg_attribute'))
        return names.map((attname) => ({ attname, type: 'domain' }))
      if (strings.join('').includes('pg_index')) return []
      // Composite serialization exposes domain text rather than payload objects.
      return [
        {
          row: Object.fromEntries(
            Object.entries(row).map(([key, value]) => [
              key,
              typeof value === 'object' ? JSON.stringify(value) : value,
            ]),
          ),
        },
      ]
    })
    const unsafe = vi.fn(async (sql: string) => {
      for (const name of names)
        expect(sql).toContain(`"${name}"::jsonb AS "${name}"`)
      if (!migrated) expect(sql).not.toContain('email_v3')
      return [row]
    })
    const database = Object.assign(query, { unsafe })
    // The fake supplies exactly the SQL interface used by this read-only helper.
    // @ts-expect-error postgres.Sql also declares unrelated connection methods.
    const snapshot = await snapshotPostgres(database)
    expect(snapshot.rows).toEqual([row])
    expect(unsafe).toHaveBeenCalledOnce()
  }
})
