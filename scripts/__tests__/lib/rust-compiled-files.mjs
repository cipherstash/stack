import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'

/**
 * The files of one library crate that `cargo build` reads when a dependent
 * compiles it with a given feature set: the manifest, `build.rs`, every module
 * file reached from `src/lib.rs`, and every file pulled in by `include_str!`,
 * `include_bytes!` or `include!`.
 *
 * Why this exists: a cache key or a `paths:` filter that names a whole crate
 * directory also names its tests, its docs, its generated bindings and every
 * module behind a feature the dependent never turns on. `eql-bindings` is the
 * case that made this matter. protect-ffi compiles it with no features, so its
 * `v4`, `encryption` and `encoding` modules (feature `stack-encrypt`) never reach
 * `index.node`, yet a pull request touching only those modules started every
 * TypeScript integration suite. This walk is what lets the key and the filters
 * name the compiled files instead, while a guard still fails the day a new
 * module is added that they do not cover.
 *
 * It errs towards including. Only one attribute removes a module: a
 * `#[cfg(feature = "NAME")]` directly above `mod NAME;`, for a feature not in
 * `enabled`. Every other `cfg` (`test`, `not(...)`, `any(...)`, target cfgs)
 * leaves the module in, and a module that is in but never compiled costs a
 * spurious cache miss, not a stale binary. What it cannot follow it reports in
 * `unresolved` rather than skipping, so a guard built on it fails instead of
 * passing having checked less: a `mod` with no file behind it, an
 * `include_str!` whose argument is not a string literal, a file it cannot read.
 *
 * String literals are kept as written, since attribute and include arguments
 * live in them, so a `mod x;` spelled inside a string reads as a declaration.
 * That errs the same way: an extra file, or an unresolved entry.
 *
 * `#[path = "…"]` is honoured. A module declared inline (`mod name { … }`)
 * whose body declares further file modules is reported as unresolved, since
 * their files resolve under a directory this walk does not track.
 *
 * Paths are repo-relative, with forward slashes.
 */
export function compiledCrateFiles(repoRoot, crateDir, enabled) {
  const files = new Set()
  const unresolved = []
  const rel = (abs) => relative(repoRoot, abs).replaceAll('\\', '/')
  const crateAbs = resolve(repoRoot, crateDir)

  const add = (abs) => {
    if (!existsSync(abs)) {
      unresolved.push(`${rel(abs)} (does not exist)`)
      return false
    }
    files.add(rel(abs))
    return true
  }

  add(join(crateAbs, 'Cargo.toml'))
  if (existsSync(join(crateAbs, 'build.rs'))) add(join(crateAbs, 'build.rs'))

  const libPath = libPathOf(readFileSync(join(crateAbs, 'Cargo.toml'), 'utf8'))
  const queue = [{ abs: join(crateAbs, libPath), owner: true }]
  while (queue.length > 0) {
    const { abs, owner } = queue.shift()
    if (files.has(rel(abs))) continue
    if (!add(abs)) continue
    const text = readFileSync(abs, 'utf8')

    for (const include of includes(text)) {
      if (include.literal === undefined) {
        unresolved.push(
          `${rel(abs)}: ${include.macro}! with a non-literal argument`,
        )
        continue
      }
      add(resolve(dirname(abs), include.literal))
    }

    // `owner`: the file owns a directory for its children — `lib.rs`,
    // `main.rs` and `mod.rs` own their own directory; `foo.rs` owns `foo/`.
    const childDir = owner ? dirname(abs) : abs.replace(/\.rs$/, '')
    for (const decl of moduleDeclarations(text)) {
      if (decl.inlineWithFileModules) {
        unresolved.push(
          `${rel(abs)}: inline \`mod ${decl.name} { … }\` declares file modules`,
        )
        continue
      }
      if (decl.inline) continue
      if (decl.feature !== undefined && !enabled.has(decl.feature)) continue
      if (decl.path !== undefined) {
        queue.push({ abs: resolve(dirname(abs), decl.path), owner: true })
        continue
      }
      const flat = join(childDir, `${decl.name}.rs`)
      const nested = join(childDir, decl.name, 'mod.rs')
      if (existsSync(flat)) queue.push({ abs: flat, owner: false })
      else if (existsSync(nested)) queue.push({ abs: nested, owner: true })
      else
        unresolved.push(
          `${rel(abs)}: \`mod ${decl.name};\` has no ${rel(flat)} or ${rel(nested)}`,
        )
    }
  }
  return { files: [...files].sort(), unresolved }
}

/** `[lib] path`, or the default `src/lib.rs`. */
function libPathOf(manifest) {
  let inLib = false
  for (const raw of manifest.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim()
    const header = /^\[([^\]]+)\]$/.exec(line)
    if (header) {
      inLib = header[1] === 'lib'
      continue
    }
    const path = inLib && /^path\s*=\s*"([^"]+)"$/.exec(line)
    if (path) return path[1]
  }
  return 'src/lib.rs'
}

/**
 * Rust source with line and block comments blanked (newlines kept), and
 * string, raw-string and char literals kept verbatim, so a `//` inside a
 * string is not read as a comment and a `"` char literal does not open one.
 */
export function stripComments(text) {
  const rawAt = /b?r(#*)"/y
  const charAt = /b?'(?:\\.[^']*|[^\\'])'/y
  const at = (pattern, i) => {
    pattern.lastIndex = i
    return pattern.exec(text)
  }
  let out = ''
  let i = 0
  while (i < text.length) {
    const raw = at(rawAt, i)
    const char = at(charAt, i)
    if (text.startsWith('//', i)) {
      while (i < text.length && text[i] !== '\n') i += 1
    } else if (text.startsWith('/*', i)) {
      let depth = 1
      i += 2
      while (i < text.length && depth > 0) {
        if (text.startsWith('/*', i)) {
          depth += 1
          i += 2
        } else if (text.startsWith('*/', i)) {
          depth -= 1
          i += 2
        } else {
          if (text[i] === '\n') out += '\n'
          i += 1
        }
      }
    } else if (raw && (i === 0 || !/[A-Za-z0-9_]/.test(text[i - 1]))) {
      const close = `"${raw[1]}`
      const end = text.indexOf(close, i + raw[0].length)
      const stop = end === -1 ? text.length : end + close.length
      out += text.slice(i, stop)
      i = stop
    } else if (char) {
      out += char[0]
      i += char[0].length
    } else if (text[i] === '"') {
      const start = i
      i += 1
      while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1
      i += 1
      out += text.slice(start, i)
    } else {
      out += text[i]
      i += 1
    }
  }
  return out
}

/**
 * Every `mod NAME;` and `mod NAME { … }` in a file, with the attributes
 * written directly above it. A declaration nested inside an inline module is
 * not returned: its file would resolve under a directory named after the
 * inline module, which this walk does not track, so the inline parent carries
 * `inlineWithFileModules` instead and the caller reports it.
 */
export function moduleDeclarations(text) {
  const source = stripComments(text)
  const found = []
  const pattern =
    /((?:#\[[^\]]*\]\s*)*)(?:pub(?:\s*\([^)]*\))?\s+)?\bmod\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])/g
  for (const match of source.matchAll(pattern)) {
    const [whole, attrs, name, end] = match
    const feature = /#\[\s*cfg\s*\(\s*feature\s*=\s*"([^"]+)"\s*\)\s*\]/.exec(
      attrs,
    )?.[1]
    const path = /#\[\s*path\s*=\s*"([^"]+)"\s*\]/.exec(attrs)?.[1]
    const decl = { name, feature, path, inline: end === '{', at: match.index }
    if (decl.inline) {
      const from = match.index + whole.length
      const body = blockBody(source, from)
      decl.span = [from, from + body.length]
      decl.inlineWithFileModules = /\bmod\s+[A-Za-z_][A-Za-z0-9_]*\s*;/.test(
        body,
      )
    }
    found.push(decl)
  }
  const spans = found.filter((decl) => decl.inline).map((decl) => decl.span)
  return found
    .filter(
      (decl) => !spans.some(([from, to]) => decl.at >= from && decl.at < to),
    )
    .map(({ at, span, ...decl }) => decl)
}

function blockBody(source, from) {
  let depth = 1
  let i = from
  while (i < source.length && depth > 0) {
    if (source[i] === '{') depth += 1
    else if (source[i] === '}') depth -= 1
    i += 1
  }
  return source.slice(from, i - 1)
}

/** `include_str!` / `include_bytes!` / `include!` calls and their argument. */
export function includes(text) {
  const source = stripComments(text)
  return [
    ...source.matchAll(
      /\b(include_str|include_bytes|include)!\s*\(\s*([^)]*)\)/g,
    ),
  ].map(([, macro, arg]) => ({
    macro,
    literal: /^"([^"\\]*)"$/.exec(arg.trim())?.[1],
  }))
}
