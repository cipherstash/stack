#!/usr/bin/env node
// Decides whether `.github/workflows/release-golang.yml` may tag a version.
//
//   node scripts/go-release-version.mjs <version> <git ref>
//
// A Go module version is immutable once the proxy has fetched it, and the
// workflow pushes its tag before `go` ever resolves it. So every way Go could
// refuse the version has to be caught here, before anything is built or
// pushed, rather than by the proxy check at the end of the run, after the tag
// exists and the version number is spent.
//
// Five rules:
//
// 1. CANONICAL SEMVER. Go accepts only `vMAJOR.MINOR.PATCH[-PRERELEASE]` with
//    no leading zeros in a numeric part or a numeric pre-release identifier,
//    no empty identifier, and no `+build` metadata (`v1.0.0+meta` is not
//    canonical, and the tag would never be the version `go get` reports).
// 2. MAJOR VERSION MATCHES THE MODULE PATH. A module whose path has no `/vN`
//    suffix may only publish v0 and v1; `v2.0.0` at that path is refused with
//    "module path must match major version". A path ending `/vN` publishes
//    major N only.
// 3. NOT A PSEUDO-VERSION. Go reads a version shaped like a pseudo-version
//    (`v0.0.0-20261012131135-deadbeefdead`, `v1.2.4-0.20261012131135-…`) as
//    a timestamp and revision to check against the repository, not as a tag,
//    so a tag of that shape builds here and fails only in `verify`, after the
//    push. Refused by the same pattern `golang.org/x/mod/module`'s
//    `IsPseudoVersion` uses.
// 4. A FINAL VERSION COMES FROM MAIN. `workflow_dispatch` runs on whatever ref
//    the dispatcher picks. A pre-release (a version with a `-suffix`) may be
//    cut from a branch, which is how a partner alpha is built from an
//    unmerged stack; a final version may not.
// 5. A FINAL VERSION SHIPS NO TEMPORARY VITAMINC PIN. vitaminc's Go bindings
//    (`github.com/cipherstash/vitaminc/bindings/go/…`) have no tags, so
//    `go.mod` names them by pseudo-version, and from time to time that is an
//    unreleased commit taken ahead of a vitaminc release, marked TEMPORARY in
//    `go.mod` and promised in the CHANGELOG to be gone before the module is
//    tagged. `release-golang.yml` tags whatever `go.mod` names, so the promise
//    is held here: a final version is refused while any vitaminc module is
//    pinned to a pseudo-version; a pre-release may carry one.

import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const GO_MOD = join(REPO_ROOT, 'languages/golang/go.mod')

const NUMERIC = /^(0|[1-9][0-9]*)$/
// golang.org/x/mod/module's pseudoVersionRE, less the `+build` suffix,
// which is refused before this is reached.
const PSEUDO_VERSION =
  /^v[0-9]+\.(0\.0-|\d+\.\d+-([^+]*\.)?0\.)\d{14}-[A-Za-z0-9]+$/
const IDENTIFIER = /^[0-9A-Za-z-]+$/
// A module of vitaminc's Go bindings and the version it is required or
// replaced at, in a go.mod stripped of its comments.
const VITAMINC_MODULE = /github\.com\/cipherstash\/vitaminc(?:\/\S+)?\s+(v\S+)/g

/** The `module` line of a go.mod. */
export function modulePathOf(goMod) {
  const match = goMod.match(/^module\s+(\S+)\s*$/m)
  if (!match) throw new Error('go.mod has no module line')
  return match[1]
}

/**
 * Every `github.com/cipherstash/vitaminc/…` module a go.mod names at a
 * pseudo-version, as `path version` strings. Comments are dropped first, so
 * the TEMPORARY note explaining a pin does not count as one.
 */
export function vitamincPseudoVersions(goMod) {
  const code = goMod.replace(/\/\/[^\n]*/g, '')
  const pins = []
  for (const match of code.matchAll(VITAMINC_MODULE)) {
    if (PSEUDO_VERSION.test(match[1])) pins.push(match[0].trim())
  }
  return pins
}

/** The major version a module path may publish: `/vN` gives N, otherwise 0 or 1. */
export function allowedMajors(modulePath) {
  const suffix = modulePath.match(/\/v([2-9]|[1-9][0-9]+)$/)
  return suffix ? [Number(suffix[1])] : [0, 1]
}

/**
 * Every reason `version` may not be released from `ref` for the module at
 * `modulePath`, whose go.mod text is `goMod`. Empty when it may.
 */
export function goReleaseVersionErrors(
  version,
  { modulePath, ref, goMod = '' },
) {
  const errors = []

  if (version.startsWith('v')) {
    errors.push(`give the version without the leading v, got '${version}'`)
    return errors
  }
  if (version.includes('+')) {
    errors.push(
      `'${version}' carries +build metadata, which a Go module version cannot`,
    )
    return errors
  }

  const dash = version.indexOf('-')
  const core = dash === -1 ? version : version.slice(0, dash)
  const pre = dash === -1 ? null : version.slice(dash + 1)

  const parts = core.split('.')
  if (parts.length !== 3 || !parts.every((part) => NUMERIC.test(part))) {
    errors.push(
      `'${version}' is not MAJOR.MINOR.PATCH with no leading zeros (e.g. 0.1.0 or 0.1.0-alpha.1)`,
    )
    return errors
  }

  if (pre !== null) {
    const ids = pre.split('.')
    for (const id of ids) {
      if (id === '') {
        errors.push(`'${version}' has an empty pre-release identifier`)
      } else if (!IDENTIFIER.test(id)) {
        errors.push(
          `pre-release identifier '${id}' may contain only [0-9A-Za-z-]`,
        )
      } else if (/^[0-9]+$/.test(id) && !NUMERIC.test(id)) {
        errors.push(`numeric pre-release identifier '${id}' has a leading zero`)
      }
    }
  }

  if (pre !== null && PSEUDO_VERSION.test(`v${version}`)) {
    errors.push(
      `'${version}' has the shape of a Go pseudo-version, which Go checks against a commit and timestamp rather than reading as a tag`,
    )
  }

  const major = Number(parts[0])
  const majors = allowedMajors(modulePath)
  if (!majors.includes(major)) {
    errors.push(
      `module ${modulePath} can only publish major version ${majors.join(' or ')}, got ${major}` +
        (majors.length > 1
          ? '; a v2+ release needs a /vN suffix on the module path first'
          : ''),
    )
  }

  if (pre === null && ref !== 'refs/heads/main') {
    errors.push(
      `a final version is released from main only, this run is on ${ref}; dispatch from main, or give a pre-release version such as ${core}-alpha.1`,
    )
  }

  const pins = vitamincPseudoVersions(goMod)
  if (pre === null && pins.length > 0) {
    errors.push(
      `a final version cannot ship vitaminc's Go bindings at a pseudo-version (go.mod names ${pins.join(', ')}); pin a vitaminc tag or a commit on vitaminc main that a release carries first, or give a pre-release version such as ${core}-alpha.1`,
    )
  }

  return errors
}

function main() {
  const [version, ref] = process.argv.slice(2)
  if (!version || !ref) {
    console.error('usage: go-release-version.mjs <version> <git ref>')
    process.exit(2)
  }
  const goMod = readFileSync(GO_MOD, 'utf8')
  const modulePath = modulePathOf(goMod)
  const errors = goReleaseVersionErrors(version, { modulePath, ref, goMod })
  for (const error of errors) console.log(`::error::${error}`)
  if (errors.length > 0) process.exit(1)
  console.log(`${modulePath} v${version} may be released from ${ref}`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main()
