#!/usr/bin/env node
// Promote the `[Unreleased]` section of CHANGELOG.md to a dated release entry
// for the version currently being released.
//
// Invoked from the `version` npm lifecycle hook (see package.json), so it runs
// automatically during `npm version` — both in CI releases and local bumps —
// after the package version has been bumped but before the version commit. The
// hook's trailing `git add .` stages the result into that commit, so the tag
// always carries an up-to-date CHANGELOG.
//
// Defensive by design: anything unexpected (no version, no `[Unreleased]`
// heading, already-promoted) logs and exits 0 so a release is never blocked.
import { readFileSync, writeFileSync } from 'node:fs'

const REPO = 'https://github.com/cipherstash/protectjs-ffi'
const FILE = 'CHANGELOG.md'

const version = (
  process.env.npm_package_version ||
  process.argv[2] ||
  ''
).replace(/^v/, '')
if (!version) {
  console.warn(
    'changelog-release: no version (npm_package_version unset) — skipping',
  )
  process.exit(0)
}

let text
try {
  text = readFileSync(FILE, 'utf8')
} catch (err) {
  console.warn(
    `changelog-release: could not read ${FILE} (${err.message}) — skipping`,
  )
  process.exit(0)
}

// Preserve the file's existing line-ending style when writing new content.
const NL = text.includes('\r\n') ? '\r\n' : '\n'

if (text.includes(`## [${version}]`)) {
  console.log(`changelog-release: [${version}] already present — skipping`)
  process.exit(0)
}

// Capture everything under `## [Unreleased]` up to the next `## [` section
// heading or the link-reference block at the bottom.
const unreleasedRe =
  /## \[Unreleased\]\r?\n([\s\S]*?)(?=\r?\n## \[|\r?\n\[Unreleased\]:|$)/
const match = text.match(unreleasedRe)
if (!match) {
  console.warn('changelog-release: no [Unreleased] section — skipping')
  process.exit(0)
}

const body = match[1].trim() || '- _No notable changes documented._'
const today = new Date().toISOString().slice(0, 10)

// Previous released version = first version heading after `[Unreleased]` (the
// topmost release). Capture the full version, including any pre-release/build
// suffix (e.g. `0.26.0-rc.1`), so compare links stay correct for those tags.
const prevMatch = text.match(/## \[(?!Unreleased\])([^\]]+)\]/)
const prev = prevMatch ? prevMatch[1] : null

// Reset `[Unreleased]` to empty and insert the promoted, dated section below
// it. A function replacer keeps `$`-sequences in the body (e.g. `$1`, `$&`)
// from being interpreted as `String.prototype.replace` patterns.
text = text.replace(
  unreleasedRe,
  () =>
    `## [Unreleased]${NL}${NL}## [${version}] - ${today}${NL}${NL}${body}${NL}`,
)

const unreleasedLink = `[Unreleased]: ${REPO}/compare/v${version}...HEAD`
const newLink = `[${version}]: ${REPO}/compare/${prev ? `v${prev}` : `v${version}^`}...v${version}`
// Repoint the `[Unreleased]` compare link at the new tag and insert the link
// for the freshly promoted version directly beneath it. The `m` flag plus `.*`
// (which never spans line terminators) keep this working for LF or CRLF; the
// function replacer avoids `$`-pattern interpretation.
if (/^\[Unreleased\]:.*$/m.test(text)) {
  text = text.replace(
    /^\[Unreleased\]:.*$/m,
    () => `${unreleasedLink}${NL}${newLink}`,
  )
} else {
  // No link-reference block to anchor on — append one so the promoted entry
  // still ships with working compare links.
  text = `${text.replace(/[\r\n]+$/, '')}${NL}${NL}${unreleasedLink}${NL}${newLink}${NL}`
}

try {
  writeFileSync(FILE, text)
} catch (err) {
  console.warn(
    `changelog-release: could not write ${FILE} (${err.message}) — skipping`,
  )
  process.exit(0)
}
console.log(
  `changelog-release: promoted [Unreleased] -> [${version}] - ${today}`,
)
