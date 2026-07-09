import { describe, expect, it } from 'vitest'
import { addJsonbCastsV3 } from '@/supabase/helpers'

// `createdAt` is a renamed property (DB column `created_at`); `email` is a
// property whose name already equals its DB column.
const propToDb = { createdAt: 'created_at', email: 'email' }

describe('addJsonbCastsV3', () => {
  it('aliases a renamed property to its DB name', () => {
    expect(addJsonbCastsV3('createdAt', propToDb)).toBe(
      'createdAt:created_at::jsonb',
    )
  })

  it('casts a property whose name equals its DB name in place', () => {
    expect(addJsonbCastsV3('email', propToDb)).toBe('email::jsonb')
  })

  it('casts a raw DB name in place, without aliasing', () => {
    expect(addJsonbCastsV3('created_at', propToDb)).toBe('created_at::jsonb')
  })

  it('resolves an already-aliased token whose name is a property', () => {
    expect(addJsonbCastsV3('e:createdAt', propToDb)).toBe('e:created_at::jsonb')
  })

  it('resolves an already-aliased token whose name is a raw DB name', () => {
    expect(addJsonbCastsV3('e:created_at', propToDb)).toBe(
      'e:created_at::jsonb',
    )
  })

  it('leaves an aliased token naming an unknown column untouched', () => {
    expect(addJsonbCastsV3('e:other', propToDb)).toBe('e:other')
  })

  it('leaves already-cast tokens untouched', () => {
    expect(addJsonbCastsV3('email::text', propToDb)).toBe('email::text')
  })

  it('leaves function calls untouched', () => {
    expect(addJsonbCastsV3('count(email)', propToDb)).toBe('count(email)')
  })

  it('leaves foreign-table (dotted) tokens untouched', () => {
    expect(addJsonbCastsV3('t.email', propToDb)).toBe('t.email')
  })

  // `lookupDbName`'s `Object.hasOwn` guard. Without it an inherited
  // `Object.prototype` member resolves truthy and gets interpolated into the
  // emitted select string (e.g. `function Object() { … }::jsonb`).
  it('does not resolve a bare Object.prototype key as a property', () => {
    expect(addJsonbCastsV3('constructor', propToDb)).toBe('constructor')
  })

  it('does not resolve an Object.prototype key inside an alias', () => {
    expect(addJsonbCastsV3('a:toString', propToDb)).toBe('a:toString')
  })

  it('maps each token of a multi-column select independently', () => {
    expect(addJsonbCastsV3('id, email, createdAt', propToDb)).toBe(
      'id, email::jsonb, createdAt:created_at::jsonb',
    )
  })
})
