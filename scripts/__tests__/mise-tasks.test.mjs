import { describe, expect, it } from 'vitest'
import { parseIncludes, parseTomlTasks } from './lib/mise-tasks.mjs'

describe('reading mise tasks', () => {
  it('keeps a shell line that starts with [ inside its task', () => {
    const text = [
      '[tasks."test:pg"]',
      'run = """',
      'listing=$(cargo test --list)',
      '[ -n "$listing" ] || { echo "no tests" >&2; exit 1; }',
      'docker run --rm postgres:17 true',
      '"""',
      '',
      '[tasks.other]',
      'run = "true"',
    ].join('\n')
    const tasks = parseTomlTasks(text, { bareTables: false })
    expect(tasks.map(({ name }) => name)).toEqual(['test:pg', 'other'])
    expect(tasks[0].block).toContain('docker run --rm postgres:17 true')
  })

  it('splits at each form of table header', () => {
    const text = [
      '[tools]',
      'node = "24"',
      '[tasks."a:b"] # a comment',
      'run = "one"',
      '[tasks.c]',
      'run = "two"',
      '[env]',
      'X = "1"',
    ].join('\n')
    const tasks = parseTomlTasks(text, { bareTables: false })
    expect(tasks.map(({ name }) => name)).toEqual(['a:b', 'c'])
    expect(tasks[1].block).not.toContain('X = "1"')
    expect(
      parseTomlTasks('["x"]\nrun = "1"\n[y]\nrun = "2"\n', {
        bareTables: true,
      }).map(({ name }) => name),
    ).toEqual(['x', 'y'])
  })

  it('reads includes that span lines', () => {
    const text = [
      '[task_config]',
      'includes = [',
      '  "a/tasks.toml",',
      "  'b',",
      ']',
      '[env]',
    ].join('\n')
    expect(parseIncludes(text)).toEqual(['a/tasks.toml', 'b'])
  })
})
