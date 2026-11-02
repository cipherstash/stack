import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  absoluteLinks,
  changelogSection,
  releaseNotes,
  releaseTag,
  unwrap,
} from '../go-release-notes.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * `release-golang.yml` puts a version's CHANGELOG section on its release
 * page. Before this, the page carried only install commands and checksums,
 * and an upgrade step that existed only in the CHANGELOG never reached the
 * people reading the release.
 */

const CHANGELOG = `# Changelog

## [Unreleased]

## [0.2.0] - 2026-12-01

### Added

- **A thing.** It wraps
  onto a second line.

## [0.1.0-rc.3] - 2026-11-02

### Upgrading

Install the bundle. See the
[permissions reference](../../packages/eql/docs/reference/permissions.md).

## [0.1.0-rc.30]

Not rc.3.
`

describe('changelogSection', () => {
  it('takes the body up to the next version heading, without its own heading', () => {
    expect(changelogSection(CHANGELOG, '0.2.0')).toBe(
      '### Added\n\n- **A thing.** It wraps\n  onto a second line.',
    )
  })

  it('matches the version exactly, not as a prefix or a pattern', () => {
    expect(changelogSection(CHANGELOG, '0.1.0-rc.3')).toContain(
      'Install the bundle.',
    )
    expect(changelogSection(CHANGELOG, '0.1.0-rc.30')).toBe('Not rc.3.')
    expect(() => changelogSection(CHANGELOG, '0x1x0-rc.3')).toThrow(
      /no "## \[0x1x0-rc\.3\]" section/,
    )
  })

  it('refuses a version with no section, naming it', () => {
    expect(() => changelogSection(CHANGELOG, '0.1.0-rc.4')).toThrow(
      /CHANGELOG\.md has no "## \[0\.1\.0-rc\.4\]" section/,
    )
  })

  it('refuses a section with nothing in it', () => {
    expect(() =>
      changelogSection('## [1.0.0]\n\n\n## [0.9.0]\n\nx\n', '1.0.0'),
    ).toThrow(/is empty/)
  })
})

describe('absoluteLinks', () => {
  const ref = releaseTag('0.1.0-rc.3')
  const blob = `https://github.com/cipherstash/stack/blob/${ref}`

  it('points a relative link at the file at the tag, resolved from languages/golang', () => {
    expect(absoluteLinks('[a](encrypt/README.md#eql-columns)', ref)).toBe(
      `[a](${blob}/languages/golang/encrypt/README.md#eql-columns)`,
    )
    expect(absoluteLinks('[b](../../packages/eql/x.md)', ref)).toBe(
      `[b](${blob}/packages/eql/x.md)`,
    )
    expect(absoluteLinks('[c](/SECURITY.md)', ref)).toBe(
      `[c](${blob}/SECURITY.md)`,
    )
  })

  it('leaves a link with a scheme, or only an anchor, alone', () => {
    for (const link of [
      '[k](https://keepachangelog.com/en/1.0.0/)',
      '[m](mailto:security@cipherstash.com)',
      '[h](#breaking)',
    ]) {
      expect(absoluteLinks(link, ref)).toBe(link)
    }
  })

  it('refuses a link that climbs out of the repository', () => {
    expect(() => absoluteLinks('[x](../../../etc/passwd)', ref)).toThrow(
      /outside the repository/,
    )
  })
})

describe('unwrap', () => {
  it('joins a wrapped paragraph and keeps blank lines between paragraphs', () => {
    expect(unwrap('one\ntwo\nthree\n\nfour\n  five')).toBe(
      'one two three\n\nfour five',
    )
  })

  it('joins a list item with its indented continuation, and starts a new item at each marker', () => {
    expect(
      unwrap(
        '- first\n  more\n- second\n1. one\n   more\n2. two\n  - nested\n    more',
      ),
    ).toBe('- first more\n- second\n1. one more\n2. two\n  - nested more')
  })

  it('never joins onto or into a heading, a table row or a quote', () => {
    const text = '### Heading\nline\n| a | b |\n| - | - |\n> quote\nnext'
    expect(unwrap(text)).toBe(
      '### Heading\nline\n| a | b |\n| - | - |\n> quote next',
    )
  })

  it('leaves a fenced code block exactly as it is', () => {
    const text = 'Run:\n\n```sh\ngo get a\ngo install b\n```\nafter\nthis'
    expect(unwrap(text)).toBe(
      'Run:\n\n```sh\ngo get a\ngo install b\n```\nafter this',
    )
  })
})

describe('the real CHANGELOG', () => {
  const changelog = readFileSync(
    join(REPO_ROOT, 'languages/golang/CHANGELOG.md'),
    'utf8',
  )
  const versions = [...changelog.matchAll(/^## \[(\d[^\]]*)\]/gm)].map(
    ([, version]) => version,
  )

  it('has one section per version', () => {
    expect(versions).toContain('0.1.0-rc.3')
    expect(new Set(versions).size).toBe(versions.length)
  })

  it.each(
    versions,
  )('gives notes for %s with no relative link left', (version) => {
    const notes = releaseNotes(changelog, version)
    expect(notes.length).toBeGreaterThan(0)
    for (const [, target] of notes.matchAll(/\]\(([^)\s]+)\)/g)) {
      expect(target).toMatch(/^(https?:|mailto:|#)/)
    }
  })
})

describe('release-golang.yml', () => {
  const workflow = readWorkflow('.github/workflows/release-golang.yml')
  const { notes, build, publish } = workflow.jobs
  const notesStep = notes.steps.find((step) => step.id === 'notes')
  const releaseStep = publish.steps.find(
    (step) => step.name === 'Create the GitHub release',
  )

  it('makes the notes in a job that cannot write and runs nothing but checkout and the script', () => {
    expect(notes.permissions).toBeUndefined()
    expect(workflow.permissions).toEqual({ contents: 'read' })
    for (const step of notes.steps) {
      if (step.uses)
        expect(step.uses).toMatch(/^actions\/checkout@[0-9a-f]{40}$/)
    }
    expect(notesStep.run).toContain(
      'node scripts/go-release-notes.mjs "$VERSION"',
    )
  })

  it('stops the release before the build when the notes fail', () => {
    expect([build.needs].flat()).toContain('notes')
    expect([publish.needs].flat()).toEqual(
      expect.arrayContaining(['notes', 'build']),
    )
  })

  it('hands the notes to publish through the environment, never into its script', () => {
    // biome-ignore lint/suspicious/noTemplateCurlyInString: a literal GitHub Actions expression.
    expect(releaseStep.env.NOTES).toBe('${{ needs.notes.outputs.notes }}')
    expect(releaseStep.run).toContain('"$NOTES"')
    expect(releaseStep.run).not.toContain('${{')
    for (const step of publish.steps) {
      expect(step.run ?? '').not.toMatch(/\bnode\b/)
    }
  })

  /**
   * Run the real step for `version`, from a scratch directory standing in for
   * the checkout's root, so the notes.md it writes lands outside the
   * repository. The script and the real CHANGELOG are copied in at their
   * paths; a symlink would not do, since the script's main-guard compares
   * argv[1], which would be the link, with its own real path.
   */
  const runNotesStep = (version) => {
    const dir = mkdtempSync(join(tmpdir(), 'go-release-notes-'))
    const output = join(dir, 'output')
    try {
      for (const file of [
        'scripts/go-release-notes.mjs',
        'languages/golang/CHANGELOG.md',
      ]) {
        mkdirSync(dirname(join(dir, file)), { recursive: true })
        copyFileSync(join(REPO_ROOT, file), join(dir, file))
      }
      const result = spawnSync('bash', ['-c', notesStep.run], {
        cwd: dir,
        encoding: 'utf8',
        env: { ...process.env, VERSION: version, GITHUB_OUTPUT: output },
      })
      return {
        status: result.status,
        stderr: result.stderr,
        written: existsSync(output) ? readFileSync(output, 'utf8') : '',
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  }

  it("the notes step's output is the script's notes for the version", () => {
    const { status, written } = runNotesStep('0.1.0-rc.3')
    expect(status).toBe(0)
    const match = written.match(
      /^notes<<(notes_[0-9a-f]{32})\n([\s\S]*)\n\1\n$/,
    )
    expect(match).not.toBeNull()
    const changelog = readFileSync(
      join(REPO_ROOT, 'languages/golang/CHANGELOG.md'),
      'utf8',
    )
    expect(match[2]).toBe(releaseNotes(changelog, '0.1.0-rc.3'))
  })

  it('the notes step fails, and writes no output, for a version with no section', () => {
    const { status, stderr, written } = runNotesStep('0.1.0-rc.999')
    expect(status).not.toBe(0)
    expect(stderr).toContain('no "## [0.1.0-rc.999]" section')
    expect(written).toBe('')
  })
})
