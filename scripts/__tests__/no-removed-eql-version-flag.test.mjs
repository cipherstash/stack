import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')

/** Tracked skills ship with the CLI and are copied into customer projects. */
function shippedSkills() {
  const out = execFileSync(
    'git',
    ['ls-files', '-z', ':(glob)skills/*/SKILL.md'],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    },
  )
  return out.split('\0').filter(Boolean)
}

describe('shipped skill eql install examples use the current CLI', () => {
  const files = shippedSkills()

  it('finds tracked shipped skills (guards against a silently-empty glob)', () => {
    expect(files.length).toBeGreaterThan(5)
    expect(files).toContain('skills/stash-drizzle/SKILL.md')
    expect(files).toContain('skills/stash-supabase/SKILL.md')
  })

  it.each(files)('%s', (file) => {
    const body = readFileSync(resolve(REPO_ROOT, file), 'utf8')
    const obsoleteExamples = body.match(
      /\bstash\s+eql\s+install\b[^\n]*--eql-version\b/g,
    )

    expect(
      obsoleteExamples ?? [],
      `${file} contains an executable stash eql install example with the removed --eql-version flag.`,
    ).toEqual([])
  })
})
