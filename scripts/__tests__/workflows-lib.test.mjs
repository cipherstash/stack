import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { triggers } from './lib/workflows.mjs'

// Seven workflow guards read their triggers through this helper. A change
// that drops a trigger would make each of them check fewer workflows, and
// pass.
describe('triggers()', () => {
  it('reads `on:` under the YAML 1.1 `true` key and under a quoted key', () => {
    expect(triggers(yaml.load('on:\n  push: {}'))).toHaveProperty('push')
    expect(triggers(yaml.load("'on':\n  push: {}"))).toHaveProperty('push')
  })

  it('keeps a trigger declared with no value', () => {
    expect(
      'workflow_dispatch' in triggers(yaml.load('on:\n  workflow_dispatch:')),
    ).toBe(true)
  })

  it('gives {} for a missing or non-object `on:`', () => {
    expect(triggers(yaml.load('name: x'))).toEqual({})
    expect(triggers(yaml.load('on: push'))).toEqual({})
    expect(triggers(undefined)).toEqual({})
  })
})
