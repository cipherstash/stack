// Compile-time tests: `pnpm run typecheck` compiles this file and nothing
// runs it. Each `@ts-expect-error` is a line that must not compile.
import type {
  Cipher,
  Keyset,
  OpenedJson,
  OpenedScalar,
  RcDate,
  RcDecimal,
  RcTimestamp,
  RcUuid,
  RecipherError,
  Result,
} from '../src/index'
import { Ciphertext, json, kinds } from '../src/index'

declare const keyset: Keyset
declare const cipher: Cipher

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
function expectType<T>(_: T): void {}
function check<_ extends true>(): void {}

// One value gives one ciphertext. The type of the ciphertext is the type the
// value decrypts to. A literal widens.
const text = await keyset.encrypt('a secret')
check<Exact<typeof text, Result<Ciphertext<string>, RecipherError>>>()
const count = await keyset.encrypt(5n)
check<Exact<typeof count, Result<Ciphertext<bigint>, RecipherError>>>()
const flag = await keyset.encrypt(true)
check<Exact<typeof flag, Result<Ciphertext<boolean>, RecipherError>>>()
const bytes = await keyset.encrypt(new Uint8Array(1))
check<Exact<typeof bytes, Result<Ciphertext<Uint8Array>, RecipherError>>>()
const when = await keyset.encrypt(new Date())
check<Exact<typeof when, Result<Ciphertext<Date>, RecipherError>>>()
declare const instant: RcTimestamp
const fine = await keyset.encrypt(instant)
check<
  Exact<typeof fine, Result<Ciphertext<Date | RcTimestamp>, RecipherError>>
>()
declare const day: RcDate
const dated = await keyset.encrypt(day)
check<Exact<typeof dated, Result<Ciphertext<RcDate>, RecipherError>>>()
declare const price: RcDecimal
const priced = await keyset.encrypt(price)
check<Exact<typeof priced, Result<Ciphertext<RcDecimal>, RecipherError>>>()
const document = await keyset.encrypt(json({ a: [1, 2n, null] }))
check<Exact<typeof document, Result<Ciphertext<OpenedJson>, RecipherError>>>()

// An array is an array.
const many = await keyset.encrypt(['a', 'b'])
check<Exact<typeof many, Result<Ciphertext<string>[], RecipherError>>>()

// Decrypting gives the type back, for one ciphertext or for an array.
if (text.isOk()) {
  const opened = await cipher.decrypt(text.value)
  check<Exact<typeof opened, Result<string, RecipherError>>>()
}
if (many.isOk()) {
  const opened = await keyset.decrypt(many.value)
  check<Exact<typeof opened, Result<string[], RecipherError>>>()
}

// A plain object needs json(..).
// @ts-expect-error: a plain object is not a value.
void keyset.encrypt({ name: 'Ada' })
// A UUID is not in the engine's value model yet.
declare const uuid: RcUuid
// @ts-expect-error: a UUID is not a value.
void keyset.encrypt(uuid)
// @ts-expect-error: undefined is not a value.
void keyset.encrypt(undefined)
// @ts-expect-error: a Map is not a value.
void keyset.encrypt(new Map())
// @ts-expect-error: bytes have no JSON form.
void json({ b: new Uint8Array(1) })
// @ts-expect-error: a date has no JSON form.
void json({ d: new Date() })
// The wrapper types are distinct.
// @ts-expect-error: an RcDate is not an RcDecimal.
expectType<RcDecimal>(day)

// A ciphertext read from stored bytes has the type of the kind named. With
// no kind, its type is any scalar.
declare const stored: Uint8Array
const typed = Ciphertext.fromBytes(stored, kinds.int64)
check<Exact<typeof typed, Result<Ciphertext<bigint>, RecipherError>>>()
const typedJson = Ciphertext.fromBytes(stored, kinds.json)
check<Exact<typeof typedJson, Result<Ciphertext<OpenedJson>, RecipherError>>>()
const untyped = Ciphertext.fromBytes(stored)
check<Exact<typeof untyped, Result<Ciphertext<OpenedScalar>, RecipherError>>>()
// @ts-expect-error: a kind is one of `kinds`.
void Ciphertext.fromBytes(stored, 'string')
