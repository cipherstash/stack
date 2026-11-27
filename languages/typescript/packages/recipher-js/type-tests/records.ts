// Compile-time tests: `pnpm run typecheck` compiles this file and nothing
// runs it. Each `@ts-expect-error` is a line that must not compile.
import type {
  Cipher,
  Keyset,
  Plaintext,
  RecipherError,
  Result,
  Stored,
  VcDate,
  VcDecimal,
  VcTimestamp,
  VcUuid,
} from '../src/index'
import { encrypt, kinds, passthrough, record } from '../src/index'

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
function check<_ extends true>(): void {}

const user = record('users', {
  id: passthrough<bigint>(),
  email: encrypt(kinds.string, { index: ['equality'] }),
  name: encrypt(kinds.string, { index: ['match'] }),
  age: encrypt(kinds.int32, { index: ['equality', 'ore'] }),
  notes: encrypt(kinds.string),
})

// The plaintext row: an integer field is a bigint at every width.
check<
  Exact<
    Plaintext<typeof user>,
    { id: bigint; email: string; name: string; age: bigint; notes: string }
  >
>()

// A field that takes a null may be null; a sealed null is stored like a
// value, a SQL null is a null in the stored row.
const nullable = record('n', {
  sealed: encrypt(kinds.int64, { index: ['equality'], null: 'sealed' }),
  sql: encrypt(kinds.string, { null: 'sql' }),
})
check<
  Exact<
    Plaintext<typeof nullable>,
    { sealed: bigint | null; sql: string | null }
  >
>()
declare const storedNullable: Stored<typeof nullable>
check<Exact<typeof storedNullable.sealed.equality, Uint8Array>>()
// @ts-expect-error: a SQL null field may be null in the stored row.
void storedNullable.sql.ciphertext

// The stored row: a ciphertext and the declared terms, and nothing else.
declare const stored: Stored<typeof user>
check<Exact<typeof stored.id, bigint>>()
check<Exact<typeof stored.email.ciphertext, Uint8Array>>()
check<Exact<typeof stored.email.equality, Uint8Array>>()
check<Exact<typeof stored.age.ore, Uint8Array>>()
// @ts-expect-error: notes declares no index, so it stores no equality term.
void stored.notes.equality
// @ts-expect-error: name stores a match term, not an equality term.
void stored.name.equality

// Each kind's type.
const all = record('all', {
  flag: encrypt(kinds.boolean),
  real: encrypt(kinds.float32),
  price: encrypt(kinds.decimal),
  day: encrypt(kinds.date),
  at: encrypt(kinds.timestamp),
  blob: encrypt(kinds.bytes),
  small: encrypt(kinds.uint8),
  id: encrypt(kinds.uuid, { index: ['equality'] }),
})
check<
  Exact<
    Plaintext<typeof all>,
    {
      flag: boolean
      real: number
      price: VcDecimal
      day: VcDate
      at: Date | VcTimestamp
      blob: Uint8Array
      small: bigint
      id: VcUuid
    }
  >
>()

declare const keyset: Keyset
declare const cipher: Cipher
const row: Plaintext<typeof user> = {
  id: 1n,
  email: 'a',
  name: 'b',
  age: 3n,
  notes: 'c',
}

// encrypt and decrypt carry the record's types, one row or many.
const one = await keyset.encrypt(user, row)
check<Exact<typeof one, Result<Stored<typeof user>, RecipherError>>>()
const many = await keyset.encrypt(user, [row, row])
check<Exact<typeof many, Result<Stored<typeof user>[], RecipherError>>>()
const opened = await cipher.decrypt(user, stored)
check<Exact<typeof opened, Result<Plaintext<typeof user>, RecipherError>>>()

// A row of another shape does not compile.
// @ts-expect-error: age is a bigint, not a number.
void keyset.encrypt(user, { ...row, age: 3 })
// @ts-expect-error: email is missing.
void keyset.encrypt(user, { id: 1n, name: 'b', age: 3n, notes: 'c' })
// @ts-expect-error: a field the record does not declare.
void keyset.encrypt(user, { ...row, extra: 1 })
// @ts-expect-error: email takes no null.
void keyset.encrypt(user, { ...row, email: null })

// One field: its stored form and its value.
const email = await keyset.encryptField(user, 'email', 'x')
check<
  Exact<typeof email, Result<Stored<typeof user>['email'], RecipherError>>
>()
const age = await cipher.decryptField(user, 'age', stored.age)
check<Exact<typeof age, Result<bigint, RecipherError>>>()
// @ts-expect-error: a field the record does not declare.
void keyset.encryptField(user, 'missing', 'x')
// @ts-expect-error: id is passed through, not encrypted.
void keyset.encryptField(user, 'id', 1n)
// @ts-expect-error: the value is the field's type.
void keyset.encryptField(user, 'age', 'x')
// @ts-expect-error: the stored form is the field's own.
void cipher.decryptField(user, 'email', stored.name)

// One field, many values: an array in is an array out.
const emails = await keyset.encryptField(user, 'email', ['x', 'y'])
check<
  Exact<typeof emails, Result<Stored<typeof user>['email'][], RecipherError>>
>()
const ages = await cipher.decryptField(user, 'age', [stored.age, stored.age])
check<Exact<typeof ages, Result<bigint[], RecipherError>>>()

// A declaration is plain data, read by any library.
check<Exact<typeof user.type, 'record'>>()
check<Exact<typeof user.name, 'users'>>()
check<Exact<typeof user.fields.email.type, 'sealed'>>()
