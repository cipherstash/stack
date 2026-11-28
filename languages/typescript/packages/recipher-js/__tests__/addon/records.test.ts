import { inspect } from 'node:util'
import { describe, expect, it } from 'vitest'
import {
  Cipher,
  checkDeclarations,
  encrypt,
  kinds,
  type Plaintext,
  passthrough,
  RcDate,
  RcDecimal,
  RcUuid,
  record,
} from '../../src/index'
import { testCipher } from '../../src/testing'

const user = record('users', {
  id: passthrough<bigint>(),
  email: encrypt(kinds.string, { index: ['equality'] }),
  name: encrypt(kinds.string, { index: ['match'] }),
  age: encrypt(kinds.int32, { index: ['equality'], null: 'sealed' }),
  score: encrypt(kinds.float64, { index: ['ore'] }),
  notes: encrypt(kinds.string, { null: 'sql' }),
})

const ada: Plaintext<typeof user> = {
  id: 7n,
  email: 'ada@example.com',
  name: 'Ada Lovelace',
  age: 36n,
  score: 99.5,
  notes: null,
}

async function cipher(): Promise<Cipher> {
  return (await testCipher()).unwrap()
}

describe('a record', () => {
  it('round-trips one row', async () => {
    const c = await cipher()
    const stored = (await c.defaultKeyset().encrypt(user, ada)).unwrap()
    expect((await c.decrypt(user, stored)).unwrap()).toEqual(ada)
    expect((await c.defaultKeyset().decrypt(user, stored)).unwrap()).toEqual(
      ada,
    )
  })

  it('stores a ciphertext and the declared terms for each sealed field', async () => {
    const c = await cipher()
    const stored = (await c.defaultKeyset().encrypt(user, ada)).unwrap()
    expect(stored.id).toBe(7n)
    expect(Object.keys(stored.email).sort()).toEqual(['ciphertext', 'equality'])
    expect(Object.keys(stored.name).sort()).toEqual(['ciphertext', 'match'])
    expect(Object.keys(stored.age).sort()).toEqual(['ciphertext', 'equality'])
    expect(Object.keys(stored.score).sort()).toEqual(['ciphertext', 'ore'])
    expect(stored.email.ciphertext).toBeInstanceOf(Uint8Array)
    expect(stored.email.equality).toBeInstanceOf(Uint8Array)
    // A field stored as SQL NULL is null when the value is absent.
    expect(stored.notes).toBeNull()
  })

  it('derives the same equality term for the same value', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const [a, b] = (await keyset.encrypt(user, [ada, ada])).unwrap()
    expect(Buffer.from(a?.email.equality ?? [])).toEqual(
      Buffer.from(b?.email.equality ?? []),
    )
    expect(Buffer.from(a?.email.ciphertext ?? [])).not.toEqual(
      Buffer.from(b?.email.ciphertext ?? []),
    )
  })

  it('takes a null where the field declares one', async () => {
    const c = await cipher()
    const row = { ...ada, age: null, notes: 'present' }
    const stored = (await c.defaultKeyset().encrypt(user, row)).unwrap()
    // A sealed null is stored like a value.
    expect(stored.age).not.toBeNull()
    expect((await c.decrypt(user, stored)).unwrap()).toEqual(row)
  })

  it('round-trips an array of rows, in order', async () => {
    const c = await cipher()
    const rows = [ada, { ...ada, id: 8n, email: 'grace@example.com', age: 45n }]
    const stored = (await c.defaultKeyset().encrypt(user, rows)).unwrap()
    expect(stored).toHaveLength(2)
    expect((await c.decrypt(user, stored)).unwrap()).toEqual(rows)
  })

  it('holds every kind', async () => {
    const everything = record('everything', {
      text: encrypt(kinds.string),
      flag: encrypt(kinds.boolean),
      small: encrypt(kinds.uint8),
      big: encrypt(kinds.int128),
      real: encrypt(kinds.float32),
      price: encrypt(kinds.decimal),
      day: encrypt(kinds.date),
      at: encrypt(kinds.timestamp),
      blob: encrypt(kinds.bytes),
    })
    const row: Plaintext<typeof everything> = {
      text: 'x',
      flag: true,
      small: 255n,
      big: -(2n ** 100n),
      real: 1.5,
      price: new RcDecimal('1.50'),
      day: new RcDate('2026-11-23'),
      at: new Date('2026-11-23T01:02:03.456Z'),
      blob: new Uint8Array([1, 2, 3]),
    }
    const c = await cipher()
    const stored = (await c.defaultKeyset().encrypt(everything, row)).unwrap()
    const opened = (await c.decrypt(everything, stored)).unwrap()
    expect(opened.text).toBe('x')
    expect(opened.flag).toBe(true)
    expect(opened.small).toBe(255n)
    expect(opened.big).toBe(-(2n ** 100n))
    expect(opened.real).toBe(1.5)
    expect((opened.price as RcDecimal).value).toBe('1.50')
    expect((opened.day as RcDate).value).toBe('2026-11-23')
    expect((opened.at as Date).getTime()).toBe(
      row.at instanceof Date ? row.at.getTime() : 0,
    )
    expect(Buffer.from(opened.blob)).toEqual(Buffer.from([1, 2, 3]))
  })
})

describe('a UUID field', () => {
  const device = record('devices', {
    id: encrypt(kinds.uuid, { index: ['equality'] }),
    name: encrypt(kinds.string),
  })
  const text = '123e4567-e89b-12d3-a456-426614174000'

  it('is stored, found by equality, and read back as an RcUuid', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const row = { id: new RcUuid(text), name: 'sensor' }
    const stored = (await keyset.encrypt(device, row)).unwrap()
    expect(Object.keys(stored.id).sort()).toEqual(['ciphertext', 'equality'])

    // A query term for the same UUID matches the stored term, and a query
    // term for another UUID does not.
    const same = (
      await keyset.encryptField(device, 'id', new RcUuid(text))
    ).unwrap()
    const other = (
      await keyset.encryptField(
        device,
        'id',
        new RcUuid('123e4567-e89b-12d3-a456-426614174001'),
      )
    ).unwrap()
    expect(Buffer.from(same.equality)).toEqual(Buffer.from(stored.id.equality))
    expect(Buffer.from(other.equality)).not.toEqual(
      Buffer.from(stored.id.equality),
    )

    const opened = (await c.decrypt(device, stored)).unwrap()
    expect(opened.id).toBeInstanceOf(RcUuid)
    expect(opened.id.value).toBe(text)
    expect(opened.name).toBe('sensor')
  })

  it('refuses UUID text that is not hyphenated hex, naming the field', async () => {
    const keyset = (await cipher()).defaultKeyset()
    for (const bad of [
      '123e4567-e89b-12d3-a456-42661417400',
      '{123e4567-e89b-12d3-a456-426614174000}',
      '123e4567-e89b-12d3-a456-42661417400g',
    ]) {
      const result = await keyset.encrypt(device, {
        id: new RcUuid(bad),
        name: 'sensor',
      })
      expect(result.isErr(), bad).toBe(true)
      expect(result.err()?.code, bad).toBe('ERR_INVALID_UUID')
      expect(result.err()?.field, bad).toBe('id')
      expect(result.err()?.record, bad).toBe('devices')
    }
  })

  it('stores and decrypts a null under each null setting, and refuses one by default', async () => {
    const nullable = record('nullable_devices', {
      sealed: encrypt(kinds.uuid, { index: ['equality'], null: 'sealed' }),
      sql: encrypt(kinds.uuid, { null: 'sql' }),
      required: encrypt(kinds.uuid),
    })
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const id = new RcUuid(text)

    const empty = { sealed: null, sql: null, required: id }
    const stored = (await keyset.encrypt(nullable, empty)).unwrap()
    // A sealed null is stored like a value, padded to a value's length.
    // A SQL null is stored as null.
    const full = (
      await keyset.encrypt(nullable, { sealed: id, sql: id, required: id })
    ).unwrap()
    expect(stored.sealed).not.toBeNull()
    expect(stored.sealed.ciphertext.length).toBe(full.sealed.ciphertext.length)
    expect(Buffer.from(stored.sealed.equality)).not.toEqual(
      Buffer.from(full.sealed.equality),
    )
    expect(stored.sql).toBeNull()

    const opened = (await c.decrypt(nullable, stored)).unwrap()
    expect(opened.sealed).toBeNull()
    expect(opened.sql).toBeNull()
    expect(opened.required.value).toBe(text)

    // A field with the default null setting takes no null.
    // @ts-expect-error: `required` has no null setting, so it takes no null.
    const refused = await keyset.encrypt(nullable, {
      sealed: id,
      sql: id,
      required: null,
    })
    expect(refused.err()?.code).toBe('stack_encrypt::dynamic_source')
    expect(refused.err()?.field).toBe('required')
    expect(refused.err()?.record).toBe('nullable_devices')
  })

  it('refuses the UUID as a string', async () => {
    const keyset = (await cipher()).defaultKeyset()
    const result = await keyset.encrypt(device, {
      // @ts-expect-error: a UUID field takes an RcUuid, not its text.
      id: text,
      name: 'sensor',
    })
    expect(result.isErr()).toBe(true)
    expect(result.err()?.code).toBe('recipher_js::field_type')
    expect(result.err()?.field).toBe('id')
    expect(result.err()?.record).toBe('devices')
  })

  it('refuses an order index when the declaration is checked', async () => {
    for (const index of ['ore', 'ope'] as const) {
      const ordered = record('devices', {
        id: encrypt(kinds.uuid, { index: [index] }),
      })
      const checked = checkDeclarations([ordered])
      expect(checked.err()?.code).toBe('stack_encrypt::dynamic_plan')
      expect(checked.err()?.fields.reason).toBe('index_not_admitted')
      expect(checked.err()?.field).toBe('id')
      expect(checked.err()?.record).toBe('devices')

      const result = await Cipher.create({ records: [ordered] })
      expect(result.err()?.fields.reason).toBe('index_not_admitted')
    }
  })
})

describe('one field', () => {
  it('encrypts alone to the form it has in a whole row', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const email = (
      await keyset.encryptField(user, 'email', 'new@example.com')
    ).unwrap()
    expect(Object.keys(email).sort()).toEqual(['ciphertext', 'equality'])
    expect((await c.decryptField(user, 'email', email)).unwrap()).toBe(
      'new@example.com',
    )

    // Its equality term is the term a whole row stores for the value.
    const row = (
      await keyset.encrypt(user, { ...ada, email: 'new@example.com' })
    ).unwrap()
    expect(Buffer.from(email.equality)).toEqual(Buffer.from(row.email.equality))

    // And a whole row takes the field in place of its own.
    const updated = { ...row, email }
    expect((await c.decrypt(user, updated)).unwrap().email).toBe(
      'new@example.com',
    )
  })

  it("opens alone from a whole row's stored field", async () => {
    const c = await cipher()
    const row = (await c.defaultKeyset().encrypt(user, ada)).unwrap()
    expect(
      (await c.defaultKeyset().decryptField(user, 'name', row.name)).unwrap(),
    ).toBe('Ada Lovelace')
  })

  it('refuses a field opened as another field of the same shape: each is sealed under its own path', async () => {
    const pair = record('pair', {
      a: encrypt(kinds.string, { index: ['equality'] }),
      b: encrypt(kinds.string, { index: ['equality'] }),
    })
    const c = await cipher()
    const row = (
      await c.defaultKeyset().encrypt(pair, { a: 'x', b: 'y' })
    ).unwrap()
    // Same shape, so this compiles and the engine reads it; only the context
    // differs. The key service refuses the key, which it binds to the
    // field path the value was sealed under.
    const result = await c.decryptField(pair, 'a', row.b)
    expect(result.err()?.code).toBe('stack_kms::retrieve_key_failed')

    // A row opened under a record of another name is refused the same way.
    const other = record('other', pair.fields)
    const moved = await c.decrypt(other, row)
    expect(moved.err()?.code).toBe('stack_kms::retrieve_key_failed')
    expect(moved.err()?.record).toBe('other')
  })

  it('encrypts and decrypts an array of one field in one call', async () => {
    const c = await cipher()
    const keyset = c.defaultKeyset()
    const emails = (
      await keyset.encryptField(user, 'email', [
        'a@example.com',
        'b@example.com',
      ])
    ).unwrap()
    expect(emails).toHaveLength(2)
    expect((await c.decryptField(user, 'email', emails)).unwrap()).toEqual([
      'a@example.com',
      'b@example.com',
    ])
  })

  it('stores a SQL null field alone as null', async () => {
    const c = await cipher()
    const notes = (
      await c.defaultKeyset().encryptField(user, 'notes', null)
    ).unwrap()
    expect(notes).toBeNull()
    expect((await c.decryptField(user, 'notes', notes)).unwrap()).toBeNull()
  })

  it('refuses a field the record passes through or does not declare, naming it', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: id is passed through.
    const passed = await keyset.encryptField(user, 'id', 1n)
    expect(passed.err()?.code).toBe('recipher_js::no_field')
    expect(passed.err()?.field).toBe('id')
    expect(passed.err()?.record).toBe('users')
    // @ts-expect-error: no such field.
    const missing = await keyset.encryptField(user, 'missing', 'x')
    expect(missing.err()?.field).toBe('missing')
  })
})

describe('a decrypted row', () => {
  it('names its fields and hides their values when inspected', async () => {
    const c = await cipher()
    const stored = (await c.defaultKeyset().encrypt(user, ada)).unwrap()
    const opened = (await c.decrypt(user, stored)).unwrap()
    const shown = inspect(opened)
    expect(shown).toContain('email: [hidden]')
    expect(shown).not.toContain('ada@example.com')
    expect(shown).not.toContain('Lovelace')
    // The fields themselves are as they were.
    expect(opened.email).toBe('ada@example.com')
    expect(Object.keys(opened)).toEqual(Object.keys(ada))
    expect({ ...opened }).toEqual(ada)
  })
})

describe('refusals', () => {
  it('an integer outside its field, naming the field', async () => {
    const c = await cipher()
    const result = await c
      .defaultKeyset()
      .encrypt(user, { ...ada, age: 2n ** 40n })
    expect(result.err()?.code).toBe('recipher_js::field_type')
    expect(result.err()?.field).toBe('age')
    expect(result.err()?.record).toBe('users')
  })

  it('a bigint outside 128 bits, naming the field', async () => {
    const c = await cipher()
    const result = await c
      .defaultKeyset()
      .encrypt(user, { ...ada, age: 2n ** 128n })
    expect(result.err()?.code).toBe('ERR_INTEGER_RANGE')
    expect(result.err()?.field).toBe('age')
  })

  it('a null where the field takes none', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: email takes no null.
    const result = await keyset.encrypt(user, { ...ada, email: null })
    expect(result.isErr()).toBe(true)
  })

  it('a row with a field the record does not declare', async () => {
    const c = await cipher()
    const row = { ...ada, extra: 'x' }
    // A row widened past the record's type, as untyped input would be.
    const result = await c
      .defaultKeyset()
      .encrypt(user, row as Plaintext<typeof user>)
    expect(result.isErr()).toBe(true)
  })

  it('a declaration the engine refuses, naming the field', async () => {
    const bad = record('bad', {
      n: encrypt(kinds.int32, { index: ['match'] }),
    })
    const checked = checkDeclarations([bad])
    expect(checked.err()?.code).toBe('stack_encrypt::dynamic_plan')
    expect(checked.err()?.field).toBe('n')
    expect(checked.err()?.record).toBe('bad')

    const c = await cipher()
    const result = await c.defaultKeyset().encrypt(bad, { n: 1n })
    expect(result.err()?.code).toBe('stack_encrypt::dynamic_plan')
  })

  it('Cipher.create refuses a bad declaration before it looks for credentials', async () => {
    const bad = record('bad', {
      flag: encrypt(kinds.boolean, { index: ['ore'] }),
    })
    const result = await Cipher.create({ records: [user, bad] })
    expect(result.err()?.code).toBe('stack_encrypt::dynamic_plan')
    expect(result.err()?.record).toBe('bad')
  })

  it('a record name that is not a plain segment, blaming the record', () => {
    for (const name of ['a/b', '']) {
      const checked = checkDeclarations([
        record(name, { x: encrypt(kinds.string) }),
      ])
      expect(checked.err()?.code).toBe('recipher_js::record_name')
      expect(checked.err()?.record).toBe(name)
      expect(checked.err()?.field).toBeUndefined()
      expect(checked.err()?.message).toContain('record name')
    }
  })

  it('a field name the engine reserves, naming the field', () => {
    for (const name of ['bind', 'context_field']) {
      const checked = checkDeclarations([
        record('r', { [name]: encrypt(kinds.string) }),
      ])
      expect(checked.err()?.code).toBe('recipher_js::reserved_field')
      expect(checked.err()?.field).toBe(name)
    }
  })

  it('a row with a record that is not a declaration', async () => {
    const keyset = (await cipher()).defaultKeyset()
    // @ts-expect-error: the first argument is not a record.
    const result = await keyset.encrypt({ name: 'users' }, ada)
    expect(result.err()?.code).toBe('recipher_js::not_a_record')
  })

  it('a stored row with a term of an index the field does not declare, naming the field', async () => {
    const c = await cipher()
    const stored = (await c.defaultKeyset().encrypt(user, ada)).unwrap()
    const stray = {
      ...stored,
      email: { ...stored.email, match: new Uint8Array([1, 2, 3]) },
    }
    const result = await c.decrypt(user, stray)
    expect(result.err()?.code).toBe('recipher_js::not_a_stored_row')
    expect(result.err()?.field).toBe('email')
  })

  it('a stored row altered in storage does not open', async () => {
    const c = await cipher()
    const stored = (await c.defaultKeyset().encrypt(user, ada)).unwrap()
    const ciphertext = Uint8Array.from(stored.email.ciphertext)
    const last = ciphertext.length - 1
    ciphertext[last] = (ciphertext[last] ?? 0) ^ 1
    const result = await c.decrypt(user, {
      ...stored,
      email: { ...stored.email, ciphertext },
    })
    expect(result.err()?.code).toBe('stack_encrypt::aead')
  })
})
