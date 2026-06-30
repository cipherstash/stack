import { describe, expect, it } from 'vitest'
import {
  buildEncryptConfig,
  EncryptedBool,
  EncryptedColumn,
  EncryptedDate,
  EncryptedField,
  EncryptedJson,
  EncryptedNumber,
  EncryptedTable,
  EncryptedText,
  EncryptedTimestampTz,
  encryptedBool,
  encryptedColumn,
  encryptedDate,
  encryptedField,
  encryptedJson,
  encryptedNumber,
  encryptedTable,
  encryptedText,
  encryptedTimestampTz,
  toEqlCastAs,
} from '@/schema'

describe('schema builders', () => {
  // -------------------------------------------------------
  // encryptedColumn
  // -------------------------------------------------------
  describe('encryptedColumn', () => {
    it('returns a EncryptedColumn with the correct name', () => {
      const col = encryptedColumn('email')
      expect(col).toBeInstanceOf(EncryptedColumn)
      expect(col.getName()).toBe('email')
    })

    it('defaults castAs to string', () => {
      const col = encryptedColumn('name')
      const built = col.build()
      expect(built.cast_as).toBe('string')
    })

    it('.dataType("string") sets castAs to string', () => {
      const col = encryptedColumn('name').dataType('string')
      expect(col.build().cast_as).toBe('string')
    })

    it('.dataType("number") sets castAs to number', () => {
      const col = encryptedColumn('age').dataType('number')
      expect(col.build().cast_as).toBe('number')
    })

    it('.dataType("boolean") sets castAs to boolean', () => {
      const col = encryptedColumn('active').dataType('boolean')
      expect(col.build().cast_as).toBe('boolean')
    })

    it('.dataType("date") sets castAs to date', () => {
      const col = encryptedColumn('created').dataType('date')
      expect(col.build().cast_as).toBe('date')
    })

    it('.dataType("bigint") sets castAs to bigint', () => {
      const col = encryptedColumn('large').dataType('bigint')
      expect(col.build().cast_as).toBe('bigint')
    })

    it('.dataType("json") sets castAs to json', () => {
      const col = encryptedColumn('meta').dataType('json')
      expect(col.build().cast_as).toBe('json')
    })

    it('.equality() adds a unique index', () => {
      const col = encryptedColumn('email').equality()
      const built = col.build()
      expect(built.indexes).toHaveProperty('unique')
      expect(built.indexes.unique).toEqual({ token_filters: [] })
    })

    it('.equality() with token filters passes them through', () => {
      const col = encryptedColumn('email').equality([{ kind: 'downcase' }])
      const built = col.build()
      expect(built.indexes.unique).toEqual({
        token_filters: [{ kind: 'downcase' }],
      })
    })

    it('.freeTextSearch() adds a match index with defaults', () => {
      const col = encryptedColumn('bio').freeTextSearch()
      const built = col.build()
      expect(built.indexes).toHaveProperty('match')
      expect(built.indexes.match).toEqual({
        tokenizer: { kind: 'ngram', token_length: 3 },
        token_filters: [{ kind: 'downcase' }],
        k: 6,
        m: 2048,
        include_original: true,
      })
    })

    it('.freeTextSearch() with custom opts overrides defaults', () => {
      const col = encryptedColumn('bio').freeTextSearch({
        tokenizer: { kind: 'standard' },
        token_filters: [],
        k: 10,
        m: 4096,
        include_original: false,
      })
      const built = col.build()
      expect(built.indexes.match).toEqual({
        tokenizer: { kind: 'standard' },
        token_filters: [],
        k: 10,
        m: 4096,
        include_original: false,
      })
    })

    it('.orderAndRange() adds an ore index', () => {
      const col = encryptedColumn('age').orderAndRange()
      const built = col.build()
      expect(built.indexes).toHaveProperty('ore')
      expect(built.indexes.ore).toEqual({})
    })

    it('.searchableJson() adds a ste_vec index and sets castAs to json', () => {
      const col = encryptedColumn('metadata').searchableJson()
      const built = col.build()
      expect(built.cast_as).toBe('json')
      expect(built.indexes).toHaveProperty('ste_vec')
      expect(built.indexes.ste_vec).toEqual({
        prefix: 'enabled',
        array_index_mode: 'all',
      })
    })

    it('chaining multiple indexes: .equality().freeTextSearch().orderAndRange()', () => {
      const col = encryptedColumn('email')
        .equality()
        .freeTextSearch()
        .orderAndRange()
      const built = col.build()

      expect(built.indexes).toHaveProperty('unique')
      expect(built.indexes).toHaveProperty('match')
      expect(built.indexes).toHaveProperty('ore')
      expect(built.indexes.unique).toEqual({ token_filters: [] })
      expect(built.indexes.ore).toEqual({})
      expect(built.indexes.match).toBeDefined()
    })

    it('.build() produces the correct schema shape', () => {
      const col = encryptedColumn('email')
        .dataType('string')
        .equality()
        .orderAndRange()
      const built = col.build()

      expect(built).toEqual({
        cast_as: 'string',
        indexes: {
          unique: { token_filters: [] },
          ore: {},
        },
      })
    })

    it('.build() with no indexes produces empty indexes object', () => {
      const col = encryptedColumn('raw')
      const built = col.build()
      expect(built).toEqual({
        cast_as: 'string',
        indexes: {},
      })
    })
  })

  // -------------------------------------------------------
  // encryptedTable
  // -------------------------------------------------------
  describe('encryptedTable', () => {
    it('creates a table with accessible column properties', () => {
      const table = encryptedTable('users', {
        email: encryptedColumn('email'),
      })
      expect(table.email).toBeInstanceOf(EncryptedColumn)
    })

    it('table.email gives back the EncryptedColumn', () => {
      const emailCol = encryptedColumn('email').equality()
      const table = encryptedTable('users', { email: emailCol })
      expect(table.email).toBe(emailCol)
    })

    it('table.tableName is correct', () => {
      const table = encryptedTable('users', {
        email: encryptedColumn('email'),
      })
      expect(table.tableName).toBe('users')
    })

    it('is an instance of EncryptedTable', () => {
      const table = encryptedTable('users', {
        email: encryptedColumn('email'),
      })
      expect(table).toBeInstanceOf(EncryptedTable)
    })

    it('table.build() produces correct config structure', () => {
      const table = encryptedTable('users', {
        email: encryptedColumn('email').equality(),
        age: encryptedColumn('age').dataType('number').orderAndRange(),
      })
      const built = table.build()

      expect(built.tableName).toBe('users')
      expect(built.columns).toEqual({
        email: {
          cast_as: 'string',
          indexes: {
            unique: { token_filters: [] },
          },
        },
        age: {
          cast_as: 'number',
          indexes: {
            ore: {},
          },
        },
      })
    })

    it('table.build() rewrites ste_vec prefix for searchableJson columns', () => {
      const table = encryptedTable('documents', {
        metadata: encryptedColumn('metadata').searchableJson(),
      })
      const built = table.build()

      expect(built.columns.metadata.cast_as).toBe('json')
      expect(built.columns.metadata.indexes.ste_vec).toEqual({
        prefix: 'documents/metadata',
        array_index_mode: 'all',
      })
    })

    it('supports multiple columns', () => {
      const table = encryptedTable('users', {
        email: encryptedColumn('email').equality(),
        name: encryptedColumn('name').freeTextSearch(),
        age: encryptedColumn('age').dataType('number').orderAndRange(),
      })

      expect(table.email).toBeInstanceOf(EncryptedColumn)
      expect(table.name).toBeInstanceOf(EncryptedColumn)
      expect(table.age).toBeInstanceOf(EncryptedColumn)
    })

    it('exposes columnBuilders as a public, read-only map of the typed builders', () => {
      const emailCol = encryptedColumn('email').equality()
      const ageCol = encryptedColumn('age').dataType('number').orderAndRange()
      const table = encryptedTable('users', {
        email: emailCol,
        age: ageCol,
      })

      // Consumers should be able to iterate the builders without reaching
      // into the built TableDefinition (`table.build().columns`) or a
      // private internal.
      expect(Object.keys(table.columnBuilders).sort()).toEqual(['age', 'email'])
      expect(table.columnBuilders.email).toBe(emailCol)
      expect(table.columnBuilders.age).toBe(ageCol)
      expect(table.columnBuilders).toBe(table.columnBuilders)
    })
  })

  // -------------------------------------------------------
  // buildEncryptConfig
  // -------------------------------------------------------
  describe('buildEncryptConfig', () => {
    it('produces { v: 1, tables: {...} } structure', () => {
      const table = encryptedTable('users', {
        email: encryptedColumn('email').equality(),
      })
      const config = buildEncryptConfig(table)

      expect(config).toEqual({
        v: 1,
        tables: {
          users: {
            email: {
              cast_as: 'string',
              indexes: {
                unique: { token_filters: [] },
              },
            },
          },
        },
      })
    })

    it('produces config with multiple tables', () => {
      const users = encryptedTable('users', {
        email: encryptedColumn('email').equality(),
      })
      const products = encryptedTable('products', {
        price: encryptedColumn('price').dataType('number').orderAndRange(),
      })
      const config = buildEncryptConfig(users, products)

      expect(config.v).toBe(1)
      expect(Object.keys(config.tables)).toHaveLength(2)
      expect(config.tables).toHaveProperty('users')
      expect(config.tables).toHaveProperty('products')
      expect(config.tables.users).toHaveProperty('email')
      expect(config.tables.products).toHaveProperty('price')
    })

    it('v is always 1', () => {
      const table = encryptedTable('t', {
        col: encryptedColumn('col'),
      })
      const config = buildEncryptConfig(table)
      expect(config.v).toBe(1)
    })

    it('config with searchableJson has correct ste_vec prefix', () => {
      const docs = encryptedTable('documents', {
        metadata: encryptedColumn('metadata').searchableJson(),
      })
      const config = buildEncryptConfig(docs)

      expect(config.tables.documents.metadata.indexes.ste_vec).toEqual({
        prefix: 'documents/metadata',
        array_index_mode: 'all',
      })
    })
  })

  // -------------------------------------------------------
  // encryptedField (EncryptedField)
  // -------------------------------------------------------
  describe('encryptedField', () => {
    it('creates a EncryptedField', () => {
      const value = encryptedField('field')
      expect(value).toBeInstanceOf(EncryptedField)
    })

    it('returns correct name', () => {
      const value = encryptedField('myField')
      expect(value.getName()).toBe('myField')
    })

    it('defaults castAs to string', () => {
      const value = encryptedField('field')
      const built = value.build()
      expect(built.cast_as).toBe('string')
    })

    it('.dataType("json").build() produces correct shape', () => {
      const value = encryptedField('field').dataType('json')
      const built = value.build()
      expect(built).toEqual({
        cast_as: 'json',
        indexes: {},
      })
    })

    it('.dataType("number").build() produces correct shape', () => {
      const value = encryptedField('field').dataType('number')
      const built = value.build()
      expect(built).toEqual({
        cast_as: 'number',
        indexes: {},
      })
    })

    it('.build() always has empty indexes', () => {
      const value = encryptedField('field').dataType('string')
      const built = value.build()
      expect(built.indexes).toEqual({})
    })
  })

  // -------------------------------------------------------
  // encryptedTable with nested EncryptedField columns
  // -------------------------------------------------------
  describe('encryptedTable with EncryptedField', () => {
    it('table.build() processes nested EncryptedField entries', () => {
      const table = encryptedTable('users', {
        profile: {
          firstName: encryptedField('firstName'),
          lastName: encryptedField('lastName').dataType('string'),
        },
      })

      const built = table.build()
      expect(built.tableName).toBe('users')
      expect(built.columns).toHaveProperty('firstName')
      expect(built.columns).toHaveProperty('lastName')
      expect(built.columns.firstName).toEqual({
        cast_as: 'string',
        indexes: {},
      })
    })
  })

  // -------------------------------------------------------
  // Strongly-typed encrypted columns
  // -------------------------------------------------------
  describe('typed encrypted columns', () => {
    describe('encryptedNumber', () => {
      it('is an EncryptedColumn with cast_as "number"', () => {
        const col = encryptedNumber('age')
        expect(col).toBeInstanceOf(EncryptedNumber)
        expect(col).toBeInstanceOf(EncryptedColumn)
        expect(col.getName()).toBe('age')
        expect(col.build().cast_as).toBe('number')
      })

      it('.equality() adds a unique index', () => {
        expect(
          encryptedNumber('age').equality().build().indexes.unique,
        ).toEqual({ token_filters: [] })
      })

      it('.orderAndRange() adds an ore index', () => {
        expect(
          encryptedNumber('age').orderAndRange().build().indexes.ore,
        ).toEqual({})
      })
    })

    describe('encryptedDate', () => {
      it('is an EncryptedColumn with cast_as "date"', () => {
        const col = encryptedDate('dob')
        expect(col).toBeInstanceOf(EncryptedDate)
        expect(col).toBeInstanceOf(EncryptedColumn)
        expect(col.build().cast_as).toBe('date')
      })

      it('supports equality and orderAndRange', () => {
        const built = encryptedDate('dob').equality().orderAndRange().build()
        expect(built.indexes).toHaveProperty('unique')
        expect(built.indexes).toHaveProperty('ore')
      })
    })

    describe('encryptedTimestampTz', () => {
      it('is an EncryptedColumn with cast_as "timestamp"', () => {
        const col = encryptedTimestampTz('occurred_at')
        expect(col).toBeInstanceOf(EncryptedTimestampTz)
        expect(col).toBeInstanceOf(EncryptedColumn)
        expect(col.build().cast_as).toBe('timestamp')
      })

      it('supports equality and orderAndRange', () => {
        const built = encryptedTimestampTz('occurred_at')
          .equality()
          .orderAndRange()
          .build()
        expect(built.indexes).toHaveProperty('unique')
        expect(built.indexes).toHaveProperty('ore')
      })
    })

    describe('encryptedText', () => {
      it('is an EncryptedColumn with cast_as "text"', () => {
        const col = encryptedText('email')
        expect(col).toBeInstanceOf(EncryptedText)
        expect(col).toBeInstanceOf(EncryptedColumn)
        expect(col.build().cast_as).toBe('text')
      })

      it('supports equality, orderAndRange and freeTextSearch', () => {
        const built = encryptedText('email')
          .equality()
          .orderAndRange()
          .freeTextSearch()
          .build()
        expect(built.indexes).toHaveProperty('unique')
        expect(built.indexes).toHaveProperty('ore')
        expect(built.indexes.match).toEqual({
          tokenizer: { kind: 'ngram', token_length: 3 },
          token_filters: [{ kind: 'downcase' }],
          k: 6,
          m: 2048,
          include_original: true,
        })
      })
    })

    describe('encryptedJson', () => {
      it('is an EncryptedColumn with cast_as "json"', () => {
        const col = encryptedJson('metadata')
        expect(col).toBeInstanceOf(EncryptedJson)
        expect(col).toBeInstanceOf(EncryptedColumn)
        expect(col.build().cast_as).toBe('json')
      })

      it('.searchableJson() adds a ste_vec index', () => {
        const built = encryptedJson('metadata').searchableJson().build()
        expect(built.cast_as).toBe('json')
        expect(built.indexes.ste_vec).toEqual({
          prefix: 'enabled',
          array_index_mode: 'all',
        })
      })

      it('ste_vec prefix is rewritten by encryptedTable.build()', () => {
        const built = encryptedTable('documents', {
          metadata: encryptedJson('metadata').searchableJson(),
        }).build()
        expect(built.columns.metadata.indexes.ste_vec).toEqual({
          prefix: 'documents/metadata',
          array_index_mode: 'all',
        })
      })
    })

    describe('encryptedBool', () => {
      it('is an EncryptedColumn with cast_as "boolean" and no indexes', () => {
        const col = encryptedBool('is_active')
        expect(col).toBeInstanceOf(EncryptedBool)
        expect(col).toBeInstanceOf(EncryptedColumn)
        expect(col.build()).toEqual({
          cast_as: 'boolean',
          indexes: {},
        })
      })
    })

    it('typed columns compose into encryptedTable / buildEncryptConfig', () => {
      const events = encryptedTable('events', {
        title: encryptedText('title').equality().freeTextSearch(),
        attendees: encryptedNumber('attendees').orderAndRange(),
        occurred_at: encryptedTimestampTz('occurred_at').orderAndRange(),
        cancelled: encryptedBool('cancelled'),
        payload: encryptedJson('payload').searchableJson(),
      })
      const config = buildEncryptConfig(events)

      expect(config.tables.events.title.cast_as).toBe('text')
      expect(config.tables.events.attendees.cast_as).toBe('number')
      expect(config.tables.events.occurred_at.cast_as).toBe('timestamp')
      expect(config.tables.events.cancelled).toEqual({
        cast_as: 'boolean',
        indexes: {},
      })
      expect(config.tables.events.payload.indexes.ste_vec?.prefix).toBe(
        'events/payload',
      )
    })
  })

  // -------------------------------------------------------
  // toEqlCastAs
  // -------------------------------------------------------
  describe('toEqlCastAs', () => {
    it.each([
      ['string', 'text'],
      ['text', 'text'],
      ['number', 'double'],
      ['bigint', 'big_int'],
      ['boolean', 'boolean'],
      ['date', 'date'],
      ['timestamp', 'timestamp'],
      ['json', 'jsonb'],
    ] as const)('maps %s -> %s', (input, expected) => {
      expect(toEqlCastAs(input)).toBe(expected)
    })
  })
})
