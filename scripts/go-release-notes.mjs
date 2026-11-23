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
// Some notes are refused rather than changed: a reference-style link
// definition (`[x]: ../file.md`), an inline link this script cannot parse,
// and notes too large for the environment variable that carries them to the
// `publish` job. Each would otherwise surface only after the tag is pushed.
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

// `publish` takes the notes in one environment variable, which Linux caps at
// 131,072 bytes, and GitHub caps a release body at 125,000 characters. The
// limit leaves room for the install text the workflow puts after the notes.
export const MAX_NOTES_BYTES = 100_000

const FENCE = /^\s*(```|~~~)/

/**
 * `lines`, each paired with whether it is inside a fenced code block. A fence
 * line itself counts as inside.
 */
function withFences(lines) {
  let fenced = false
  return lines.map((line) => {
    if (FENCE.test(line)) {
      fenced = !fenced
      return { line, fenced: true }
    }
    return { line, fenced }
  })
}

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
  // A `## ` line inside a fence, such as a shell comment, is not a heading.
  const rest = withFences(lines.slice(start + 1))
  let end = rest.findIndex(
    ({ line, fenced }) => !fenced && line.startsWith('## '),
  )
  end = end === -1 ? lines.length : start + 1 + end
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

// An inline link or image: `[text](target)`, `[text](<target>)`, with an
// optional title. The text may hold one level of brackets.
const LINK =
  /(!?)\[((?:[^[\]]|\[[^\]]*\])*)\]\((?:<([^>\n]*)>|([^()\s<>]+))((?:\s+(?:"[^"]*"|'[^']*'))?)\)/g
// What is left of a link the pattern above could not parse: `](` not followed
// by a scheme or an anchor.
const UNREWRITTEN = /\]\(\s*<?(?![a-z][a-z0-9+.-]*:|#)/i
const isAbsolute = (target) =>
  /^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('#')

/**
 * `line` split into text and code spans: `[text, code, text, code, …]`. A
 * code span opens with a run of backticks and closes at the next run of the
 * same length; an unclosed run is text.
 */
function splitCodeSpans(line) {
  const parts = []
  let from = 0
  let i = 0
  while (i < line.length) {
    if (line[i] !== '`') {
      i++
      continue
    }
    let j = i
    while (line[j] === '`') j++
    const run = j - i
    let k = j
    let close = -1
    while (k < line.length) {
      if (line[k] !== '`') {
        k++
        continue
      }
      let m = k
      while (line[m] === '`') m++
      if (m - k === run) {
        close = m
        break
      }
      k = m
    }
    if (close === -1) {
      i = j
      continue
    }
    parts.push(line.slice(from, i), line.slice(i, close))
    from = close
    i = close
  }
  parts.push(line.slice(from))
  return parts
}

/**
 * `markdown` with every relative inline link target rewritten to the file at
 * `ref` on github.com: `/blob/` for a link, `/raw/` for an image, so the image
 * shows. A target with a scheme (`https:`, `mailto:`) or that is only an
 * anchor (`#heading`) is left alone, and so is everything in a fenced code
 * block or a code span. A target that resolves outside the repository, or a
 * link this cannot parse, is refused.
 */
export function absoluteLinks(markdown, ref) {
  const rewrite = (link, bang, text, angle, bare, title) => {
    const target = angle ?? bare
    if (isAbsolute(target)) return link
    const hash = target.indexOf('#')
    const path = hash === -1 ? target : target.slice(0, hash)
    const anchor = hash === -1 ? '' : target.slice(hash)
    const resolved = posix.normalize(
      path.startsWith('/') ? path.slice(1) : posix.join(CHANGELOG_DIR, path),
    )
    if (resolved === '..' || resolved.startsWith('../')) {
      throw new Error(`link target ${target} is outside the repository`)
    }
    const kind = bang ? 'raw' : 'blob'
    return `${bang}[${text}](${REPOSITORY_URL}/${kind}/${ref}/${encodeURI(resolved)}${anchor}${title})`
  }
  return withFences(markdown.split('\n'))
    .map(({ line, fenced }) => {
      if (fenced) return line
      return splitCodeSpans(line)
        .map((part, index) => {
          if (index % 2 === 1) return part
          const rewritten = part.replace(LINK, rewrite)
          const left = rewritten.replace(LINK, '')
          if (UNREWRITTEN.test(left)) {
            throw new Error(
              `cannot rewrite the link in "${line.trim()}"; write it as [text](path)`,
            )
          }
          return rewritten
        })
        .join('')
    })
    .join('\n')
}

// A line that starts a block of its own rather than continuing the one above.
const BLOCK_START = /^\s*(#{1,6}\s|[-*+]\s|\d+[.)]\s|>|\||```|~~~)/
const LIST_ITEM = /^\s*([-*+]|\d+[.)])\s/
// Two trailing spaces or a trailing backslash: a line break the author meant.
const HARD_BREAK = /( {2}|\\)$/
const INDENTED = /^( {4}|\t)/

/**
 * `markdown` with each soft-wrapped paragraph and list item joined into one
 * line. A line joins the one above when both have text and it does not start
 * a block (a heading, a list item, a quote, a table row or a fence); its
 * leading whitespace becomes one space. Fenced and indented code blocks,
 * headings and table rows are never joined onto, nor is a line that ends in
 * a hard break. An indented line after a blank line is code outside a list,
 * and more of the item inside one.
 */
export function unwrap(markdown) {
  const out = []
  let fenced = false
  let joinable = false
  let blankBefore = true
  let inList = false
  let indentedCode = false
  for (const line of markdown.split('\n')) {
    const blank = line.trim() === ''
    if (FENCE.test(line)) {
      fenced = !fenced
      out.push(line)
      joinable = false
      blankBefore = false
      continue
    }
    if (fenced || blank) {
      out.push(line)
      joinable = false
      blankBefore = blank
      continue
    }
    if (indentedCode && INDENTED.test(line)) {
      out.push(line)
      continue
    }
    indentedCode = false
    if (blankBefore && !inList && INDENTED.test(line)) {
      indentedCode = true
      out.push(line)
      joinable = false
      blankBefore = false
      continue
    }
    if (LIST_ITEM.test(line)) inList = true
    else if (/^\S/.test(line)) inList = false
    blankBefore = false
    if (joinable && !BLOCK_START.test(line)) {
      out[out.length - 1] =
        `${out[out.length - 1].trimEnd()} ${line.trimStart()}`
      joinable = !HARD_BREAK.test(line)
      continue
    }
    out.push(line)
    joinable = !/^\s*(#{1,6}\s|\|)/.test(line) && !HARD_BREAK.test(line)
  }
  return out.join('\n')
}

/** The release notes for `version`, from the text of the CHANGELOG. */
export function releaseNotes(changelog, version) {
  const section = changelogSection(changelog, version)
  for (const { line, fenced } of withFences(section.split('\n'))) {
    if (!fenced && /^ {0,3}\[[^\]]+\]:/.test(line)) {
      throw new Error(
        `"${line.trim()}" is a reference-style link definition, which the release page cannot resolve; write the link inline, as [text](path)`,
      )
    }
  }
  const notes = unwrap(absoluteLinks(section, releaseTag(version)))
  const bytes = Buffer.byteLength(notes, 'utf8')
  if (bytes > MAX_NOTES_BYTES) {
    throw new Error(
      `the notes for ${version} are ${bytes} bytes; the limit is ${MAX_NOTES_BYTES}. Shorten the section, or link to the CHANGELOG for the detail`,
    )
  }
  return notes
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
