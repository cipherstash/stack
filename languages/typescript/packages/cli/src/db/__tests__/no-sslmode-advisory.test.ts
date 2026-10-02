import pg from 'pg'
import { describe, expect, it } from 'vitest'
import { buildPgClientConfig } from '../config.js'

describe('#822 — no upstream sslmode advisory', () => {
  it('constructing a client via the factory emits no process warning', async () => {
    const warnings: string[] = []
    const listener = (w: Error) => warnings.push(w.message)
    process.on('warning', listener)
    new pg.Client(
      buildPgClientConfig('postgres://u:p@h:5432/db?sslmode=require'),
    )
    await new Promise((resolve) => setTimeout(resolve, 200))
    process.off('warning', listener)
    expect(warnings.filter((m) => m.includes('SECURITY WARNING'))).toEqual([])
  })
})
