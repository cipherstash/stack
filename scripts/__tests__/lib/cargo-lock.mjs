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
