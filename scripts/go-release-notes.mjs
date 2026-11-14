#!/usr/bin/env node
// Writes the release notes `.github/workflows/release-golang.yml` puts on a
// Go module release: the version's section of languages/golang/CHANGELOG.md.
//
//   node scripts/go-release-notes.mjs <version>
//
// The notes are printed to stdout. A version with no CHANGELOG section, or an
// empty one, is refused, so a release cannot ship without notes. The workflow
// runs this in its `notes` job, which `build` waits for, so a missing section
// stops the release before anything is built.
//
// The section is changed in two ways on its way to the release page:
//
// 1. RELATIVE LINKS BECOME ABSOLUTE. A link in the CHANGELOG is relative to
//    languages/golang/, and resolves on github.com only when the page is that
//    file. On a release page it would point nowhere, so each one is rewritten
//    to the file at the version's tag, which is never moved once pushed.
// 2. SOFT-WRAPPED LINES ARE JOINED. The CHANGELOG wraps its prose at 80
//    columns. GitHub renders a release body as it renders a comment, with
//    every newline a line break, so wrapped paragraphs and list items would
//    show as ragged lines. Each paragraph and list item is joined into one
//    line; fenced code blocks are left as they are.
//
// Node built-ins only: the `notes` job runs no third-party code, which is why
// `publish`, the job that can write, may take its output as the release body.

import { readFileSync } from 'node:fs'
import { join, posix, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const CHANGELOG = join(REPO_ROOT, 'languages/golang/CHANGELOG.md')
// The CHANGELOG's directory, relative to the repository root: its relative
// links resolve from here.
const CHANGELOG_DIR = 'languages/golang'
const REPOSITORY_URL = 'https://github.com/cipherstash/stack'

const escapeRegExp = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** The tag `release-golang.yml` pushes for `version`. */
export const releaseTag = (version) => `languages/golang/v${version}`

/**
 * The body of the `## [<version>]` section of `changelog`, without its
 * heading: everything up to the next `## ` heading, with the blank lines at
 * either end dropped. Throws when there is no such section, or it is empty.
 */
export function changelogSection(changelog, version) {
  const heading = new RegExp(`^## \\[${escapeRegExp(version)}\\](?:\\s|$)`)
  const lines = changelog.split('\n')
  const start = lines.findIndex((line) => heading.test(line))
  if (start === -1) {
    throw new Error(
      `languages/golang/CHANGELOG.md has no "## [${version}]" section; add one with this release's changes before releasing it`,
    )
  }
  let end = lines.findIndex((line, i) => i > start && line.startsWith('## '))
  if (end === -1) end = lines.length
  const body = lines
    .slice(start + 1, end)
    .join('\n')
    .trim()
  if (body === '') {
    throw new Error(
      `the "## [${version}]" section of languages/golang/CHANGELOG.md is empty`,
    )
  }
  return body
}

/**
 * `markdown` with every relative inline link target, `[text](target)`,
 * rewritten to the file at `ref` on github.com. A target with a scheme
 * (`https:`, `mailto:`) or that is only an anchor (`#heading`) is left alone;
 * a target that resolves outside the repository is refused.
 */
export function absoluteLinks(markdown, ref) {
  return markdown.replace(/\]\(([^)\s]+)\)/g, (link, target) => {
    if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#')) {
      return link
    }
    const hash = target.indexOf('#')
    const path = hash === -1 ? target : target.slice(0, hash)
    const anchor = hash === -1 ? '' : target.slice(hash)
    const resolved = posix.normalize(
      path.startsWith('/') ? path.slice(1) : posix.join(CHANGELOG_DIR, path),
    )
    if (resolved === '..' || resolved.startsWith('../')) {
      throw new Error(`link target ${target} is outside the repository`)
    }
    return `](${REPOSITORY_URL}/blob/${ref}/${resolved}${anchor})`
  })
}

const FENCE = /^\s*(```|~~~)/
// A line that starts a block of its own rather than continuing the one above.
const BLOCK_START = /^\s*(#{1,6}\s|[-*+]\s|\d+[.)]\s|>|\||```|~~~)/

/**
 * `markdown` with each soft-wrapped paragraph and list item joined into one
 * line. A line joins the one above when both have text and it does not start
 * a block (a heading, a list item, a quote, a table row or a fence); its
 * leading whitespace becomes one space. Fenced code blocks, headings and
 * table rows are never joined onto.
 */
export function unwrap(markdown) {
  const out = []
  let fenced = false
  let joinable = false
  for (const line of markdown.split('\n')) {
    if (FENCE.test(line)) {
      fenced = !fenced
      out.push(line)
      joinable = false
      continue
    }
    if (fenced || line.trim() === '') {
      out.push(line)
      joinable = false
      continue
    }
    if (joinable && !BLOCK_START.test(line)) {
      out[out.length - 1] = `${out[out.length - 1].trimEnd()} ${line.trim()}`
      continue
    }
    out.push(line)
    joinable = !/^\s*(#{1,6}\s|\|)/.test(line)
  }
  return out.join('\n')
}

/** The release notes for `version`, from the text of the CHANGELOG. */
export function releaseNotes(changelog, version) {
  return unwrap(
    absoluteLinks(changelogSection(changelog, version), releaseTag(version)),
  )
}

function main() {
  const [version] = process.argv.slice(2)
  if (!version) {
    console.error('usage: go-release-notes.mjs <version>')
    process.exit(2)
  }
  try {
    process.stdout.write(
      `${releaseNotes(readFileSync(CHANGELOG, 'utf8'), version)}\n`,
    )
  } catch (error) {
    // stderr: the workflow takes stdout as the notes.
    console.error(`::error::${error.message}`)
    process.exit(1)
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
