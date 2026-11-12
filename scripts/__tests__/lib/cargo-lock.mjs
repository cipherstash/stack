/**
 * The packages a `Cargo.lock` records with no `source` line: the crates its
 * workspace compiles from this tree by path, the workspace's own members
 * among them. A new path dependency appears here, so a test that derives a
 * `paths:` filter or a cache key from this list fails until it follows.
 */
export function pathPackageNames(lock) {
  return lock
    .split('[[package]]')
    .slice(1)
    .filter((block) => !/^source = /m.test(block))
    .map((block) => {
      const name = /^name = "([^"]+)"/m.exec(block)?.[1]
      if (!name) throw new Error(`a Cargo.lock package with no name:\n${block}`)
      return name
    })
}

/**
 * Every `name` package a `Cargo.lock` records, as its version, source and
 * checksum, sorted by version. The version alone is not enough: a git source
 * or a `[patch.crates-io]` fork can keep the version number while resolving
 * different code, and the source and checksum are what tell them apart.
 */
export function lockedPackages(source, name) {
  const field = (block, key) =>
    new RegExp(`^${key} = "([^"]*)"$`, 'm').exec(block)?.[1] ?? null
  return source
    .split(/^\[\[package\]\]$/m)
    .slice(1)
    .filter((block) => new RegExp(`^name = "${name}"$`, 'm').test(block))
    .map((block) => ({
      version: field(block, 'version'),
      source: field(block, 'source'),
      checksum: field(block, 'checksum'),
    }))
    .filter((pkg) => pkg.version)
    .sort((a, b) => a.version.localeCompare(b.version))
}
