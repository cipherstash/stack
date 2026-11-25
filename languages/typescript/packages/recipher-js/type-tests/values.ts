// Compile-time tests: `pnpm run typecheck` compiles this file and nothing
// runs it. Each `@ts-expect-error` is a line that must not compile.
import type {
  Cipher,
  Json,
  Keyset,
  OpenedJson,
  OpenedScalar,
  RecipherError,
  Result,
  Value,
  VcDate,
  VcDecimal,
  VcTimestamp,
  VcUuid,
} from '../src/index'
import { Ciphertext, json, kinds } from '../src/index'

declare const keyset: Keyset
declare const cipher: Cipher

type Exact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false
function expectType<T>(_: T): void {}
function check<_ extends true>(): void {}

// One value is one ciphertext, typed by what it opens as. A literal widens.
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
declare const instant: VcTimestamp
const fine = await keyset.encrypt(instant)
check<
  Exact<typeof fine, Result<Ciphertext<Date | VcTimestamp>, RecipherError>>
>()
declare const day: VcDate
const dated = await keyset.encrypt(day)
check<Exact<typeof dated, Result<Ciphertext<VcDate>, RecipherError>>>()
declare const price: VcDecimal
const priced = await keyset.encrypt(price)
check<Exact<typeof priced, Result<Ciphertext<VcDecimal>, RecipherError>>>()
const document = await keyset.encrypt(json({ a: [1, 2n, null] }))
check<Exact<typeof document, Result<Ciphertext<OpenedJson>, RecipherError>>>()

// An array is an array.
const many = await keyset.encrypt(['a', 'b'])
check<Exact<typeof many, Result<Ciphertext<string>[], RecipherError>>>()

// Decrypting gives the type back, one or many.
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
// @ts-expect-error: a plain object is not a value.
void keyset.encrypt({ a: 1 })
const plainObject = { a: 1 }
// @ts-expect-error: a plain object is not a `Json`, though it has a `toString`.
expectType<Json>(plainObject)
// @ts-expect-error: a plain object is not a `Value`.
expectType<Value>(plainObject)
// What `json(..)` returns is both.
expectType<Json>(json({ a: 1 }))
expectType<Value>(json({ a: 1 }))
// A UUID is not in the engine's value model yet.
declare const uuid: VcUuid
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
// @ts-expect-error: a VcDate is not a VcDecimal.
expectType<VcDecimal>(day)

// A ciphertext read from stored bytes is typed by the kind named, and as
// any scalar when none is.
declare const stored: Uint8Array
const typed = Ciphertext.fromBytes(stored, kinds.int64)
check<Exact<typeof typed, Result<Ciphertext<bigint>, RecipherError>>>()
const typedJson = Ciphertext.fromBytes(stored, kinds.json)
check<Exact<typeof typedJson, Result<Ciphertext<OpenedJson>, RecipherError>>>()
const untyped = Ciphertext.fromBytes(stored)
check<Exact<typeof untyped, Result<Ciphertext<OpenedScalar>, RecipherError>>>()
// @ts-expect-error: a kind is one of `kinds`.
void Ciphertext.fromBytes(stored, 'string')
