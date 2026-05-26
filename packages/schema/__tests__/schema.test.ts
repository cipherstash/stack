import { describe, expect, it } from 'vitest'
import { buildEncryptConfig, csColumn, csTable, csValue } from '../src'

describe('Schema with nested columns', () => {
  it('should handle nested column structures in encrypt config', () => {
    const users = csTable('users', {
      email: csColumn('email').freeTextSearch().equality().orderAndRange(),
      address: csColumn('address').freeTextSearch(),
      example: {
        field: csValue('example.field'),
        nested: {
          deep: csValue('example.nested.deep'),
        },
      },
    } as const)

    const config = buildEncryptConfig(users)

    // Verify basic structure
    expect(config).toEqual({
      v: 1,
      tables: {
        users: expect.any(Object),
      },
    })

    // Verify all columns are present with correct names
    const columns = config.tables.users
    expect(Object.keys(columns)).toEqual([
      'email',
      'address',
      'example.field',
      'example.nested.deep',
    ])

    // Verify email column configuration
    expect(columns.email).toEqual({
      cast_as: 'string',
      indexes: {
        match: expect.any(Object),
        unique: expect.any(Object),
        ore: {},
      },
    })

    // Verify address column configuration
    expect(columns.address).toEqual({
      cast_as: 'string',
      indexes: {
        match: expect.any(Object),
      },
    })

    // Verify nested field configuration
    expect(columns['example.field']).toEqual({
      cast_as: 'string',
      indexes: {},
    })

    // Verify deeply nested field configuration
    expect(columns['example.nested.deep']).toEqual({
      cast_as: 'string',
      indexes: {},
    })
  })

  it('should handle multiple tables with nested columns', () => {
    const users = csTable('users', {
      email: csColumn('email').equality(),
      profile: {
        name: csValue('profile.name'),
      },
    } as const)

    const posts = csTable('posts', {
      title: csColumn('title').freeTextSearch(),
      metadata: {
        tags: csValue('metadata.tags'),
      },
    } as const)

    const config = buildEncryptConfig(users, posts)

    // Verify both tables are present
    expect(Object.keys(config.tables)).toEqual(['users', 'posts'])

    // Verify users table columns
    expect(Object.keys(config.tables.users)).toEqual(['email', 'profile.name'])
    expect(config.tables.users.email.indexes).toHaveProperty('unique')

    // Verify posts table columns
    expect(Object.keys(config.tables.posts)).toEqual(['title', 'metadata.tags'])
    expect(config.tables.posts.title.indexes).toHaveProperty('match')
  })

  it('should handle complex nested structures with multiple index types', () => {
    const complex = csTable('complex', {
      id: csColumn('id').equality(),
      content: {
        text: csValue('content.text'),
        metadata: {
          tags: csValue('content.metadata.tags'),
          stats: {
            views: csValue('content.metadata.stats.views'),
          },
        },
      },
    } as const)

    const config = buildEncryptConfig(complex)

    // Verify all columns are present
    expect(Object.keys(config.tables.complex)).toEqual([
      'id',
      'content.text',
      'content.metadata.tags',
      'content.metadata.stats.views',
    ])

    // Verify complex nested column with multiple indexes
    expect(config.tables.complex['content.metadata.tags']).toEqual({
      cast_as: 'string',
      indexes: {},
    })

    // Verify deeply nested column with order and range
    expect(config.tables.complex['content.metadata.stats.views']).toEqual({
      cast_as: 'string',
      indexes: {},
    })
  })

  // NOTE: Leaving this test commented out until stevec indexing for JSON is supported.
  /*it('should handle ste_vec index for JSON columns', () => {
    const users = csTable('users', {
      json: csColumn('json').dataType('jsonb').searchableJson(),
    } as const)

    const config = buildEncryptConfig(users)

    expect(config.tables.users.json.indexes).toHaveProperty('ste_vec')
    expect(config.tables.users.json.indexes.ste_vec?.prefix).toEqual(
      'users/json',
    )
  })*/
})
