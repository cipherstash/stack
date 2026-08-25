import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { packageReadmePathspecs } from './lib/package-readmes.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'

/** Tracked executable examples that describe the current public surface. */
function publicCommandDocs() {
  const out = execFileSync(
    'git',
    [
      'ls-files',
      '-z',
      ':(glob)skills/*/SKILL.md',
      // Derived, not written down: two package roots sit deeper than one level
      // and `:(glob)` does not cross `/`. See `lib/package-readmes.mjs`.
      ...packageReadmePathspecs(),
      'docs/reference/supabase-sdk.md',
    ],
    {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    },
  )
  return out.split('\0').filter(Boolean)
}

function obsoleteEqlInstallExamples(body) {
  return [
    ...body.matchAll(/```(?:bash|sh|shell|zsh)[^\n]*\r?\n([\s\S]*?)```/gi),
  ].flatMap(
    (match) =>
      match[1]
        .replace(/\\\r?\n[ \t]*/g, ' ')
        .match(
          /^[ \t]*(?:\$[ \t]+)?(?:(?:bunx|npx)[ \t]+|(?:pnpm|yarn)[ \t]+dlx[ \t]+)?stash[ \t]+eql[ \t]+install\b[^\n]*--eql-version\b[^\n]*/gm,
        ) ?? [],
  )
}

describe('obsolete eql install example detection', () => {
  it.each([
    'stash',
    'npx stash',
    'bunx stash',
    'pnpm dlx stash',
    'yarn dlx stash',
  ])('detects the documented %s runner form', (runner) => {
    const shellExample = `\`\`\`bash\n${runner} eql install --eql-version 3\n\`\`\``

    expect(obsoleteEqlInstallExamples(shellExample)).toHaveLength(1)
  })

  it('does not treat explanatory prose as an executable example', () => {
    const prose =
      'The removed stash eql install --eql-version flag is no longer accepted.'

    expect(obsoleteEqlInstallExamples(prose)).toEqual([])
  })

  it('detects a backslash-wrapped executable shell command', () => {
    const shellExample = [
      '```bash',
      'stash eql install \\',
      '  --eql-version 3',
      '```',
    ].join('\n')

    expect(obsoleteEqlInstallExamples(shellExample)).toHaveLength(1)
  })
})

describe('public eql install examples use the current CLI', () => {
  const files = publicCommandDocs()

  it('finds tracked public command docs (guards against a silently-empty glob)', () => {
    expect(files).not.toHaveLength(0)
    expect(files).toContain('skills/stash-drizzle/SKILL.md')
    expect(files).toContain('skills/stash-supabase/SKILL.md')
    expect(files).toContain('packages/stack/README.md')
    expect(files).toContain('docs/reference/supabase-sdk.md')
    // The two roots nested deeper than `packages/*`. Pinned by name because
    // they are what the hardcoded `:(glob)packages/*/README.md` silently
    // missed: `:(glob)` does not cross `/`, so it selected the EQL subtree
    // ROOT's README — which ships in no tarball — instead of the package's.
    expect(files).toContain('packages/eql/packages/eql/README.md')
    expect(files).toContain(
      'packages/protect-ffi/platforms/linux-x64-gnu/README.md',
    )
  })

  it.each(files)('%s', (file) => {
    const body = readFileSync(resolve(REPO_ROOT, file), 'utf8')
    const obsoleteExamples = obsoleteEqlInstallExamples(body)

    expect(
      obsoleteExamples,
      `${file} contains an executable stash eql install example with the removed --eql-version flag.`,
    ).toEqual([])
  })
})
