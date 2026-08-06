#!/usr/bin/env node
// Print the CHANGELOG.md section body for a given version, for use as GitHub
// release notes. Usage: node scripts/changelog-extract.mjs 0.26.0
//
// Exits non-zero if the section is missing so the caller can fall back to a
// generic body rather than publishing an empty release.
import { readFileSync } from 'node:fs'

const version = (process.argv[2] || '').replace(/^v/, '')
if (!version) {
  console.error('usage: changelog-extract.mjs <version>')
  process.exit(2)
}

let text
try {
  text = readFileSync('CHANGELOG.md', 'utf8')
} catch (err) {
  // A missing/unreadable file (or wrong cwd) should read as "no notes here"
  // — a concise message and non-zero exit so the caller falls back cleanly,
  // not a raw stack trace.
  console.error(
    `changelog-extract: could not read CHANGELOG.md (${err.message})`,
  )
  process.exit(1)
}
// The trailing compare-link block (`[label]: <url>` lines at the very end of
// the file) sits below the last section. Strip it up front — anchored to EOF —
// so it can't leak into that section's notes, while a reference-style link
// *inside* a section body (never at EOF) is left untouched. This is stricter
// than treating any column-0 `[x]:` line as the boundary, which would truncate
// notes that use reference-style Markdown links.
const withoutLinks = text.replace(
  /(?:\r?\n)*(?:\[[^\]]+\]:[^\r\n]*(?:\r?\n|$))+\s*$/,
  '\n',
)

// Escape every regex metacharacter — semver pre-release/build tags can contain
// `+`, `.` and other special chars — so the heading is matched literally.
const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
// Match the version heading, then capture until the next `## [` section or the
// end of the (link-stripped) file. `\r?\n` tolerates CRLF files.
const re = new RegExp(
  `## \\[${escaped}\\][^\\r\\n]*\\r?\\n([\\s\\S]*?)(?=\\r?\\n## \\[|$)`,
)
const match = withoutLinks.match(re)
if (!match) {
  console.error(`changelog-extract: no section for ${version}`)
  process.exit(1)
}

process.stdout.write(`${match[1].trim()}\n`)
