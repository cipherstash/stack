#!/usr/bin/env node
// The fixture index owns enrollment; the command adds the earlier runners.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export const coreGoTests = [
  'TestStackConformance',
  'TestDeclarationConformance',
  'TestRuntimeConformance',
  'TestReadConformance',
  'TestContextConformance',
  'TestContextBoundaries',
  'TestFixtureConformanceRequiresGuest',
]

export function goSelection(index) {
  const tests = new Set(coreGoTests)
  for (const profile of index.profiles) {
    for (const requirement of profile.requirements) {
      for (const name of requirement.go_tests) {
        if (!/^Test[A-Za-z0-9_]+$/.test(name)) {
          throw new Error(`Invalid Go test name: ${name}`)
        }
        tests.add(name)
      }
    }
  }
  return `^(${[...tests].sort().join('|')})$`
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const index = JSON.parse(
    readFileSync(
      new URL(
        '../conformance/stack-encrypt/v1/fixture-profiles.json',
        import.meta.url,
      ),
      'utf8',
    ),
  )
  process.stdout.write(`${goSelection(index)}\n`)
}
