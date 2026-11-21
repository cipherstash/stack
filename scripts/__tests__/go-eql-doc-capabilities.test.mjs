import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const catalog = readFileSync('languages/golang/encrypt/eql/eql_gen.go', 'utf8')
const guide = readFileSync('languages/golang/cmd/stashgen/README.md', 'utf8')

describe('Go EQL capability reference', () => {
  it('lists exactly the EQL types the generated catalog says stashgen can produce', () => {
    const producible = new Set(
      [...catalog.matchAll(/\{Name: "([^"]+)"[^\n]*\bProducible: true\b/g)].map(
        ([, name]) => name,
      ),
    )
    expect(producible.size).toBeGreaterThan(0)

    const tableStart = guide.indexOf('| `encrypt_into` | Go field |')
    expect(tableStart).toBeGreaterThan(-1)
    const rows = guide.slice(tableStart).split('\n').slice(2)
    const documented = []
    for (const row of rows) {
      if (!row.startsWith('|')) break
      const firstCell = row.split('|')[1]
      documented.push(
        ...[...firstCell.matchAll(/`([A-Za-z][A-Za-z0-9]*)`/g)].map(
          ([, name]) => name,
        ),
      )
    }

    expect(new Set(documented).size).toBe(documented.length)
    expect(new Set(documented)).toEqual(producible)
  })
})
