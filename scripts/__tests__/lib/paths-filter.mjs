const globPrefix = (pattern) => {
  const segments = pattern.split('/')
  const at = segments.findIndex((segment) => /[*?[]/.test(segment))
  return (at === -1 ? segments : segments.slice(0, at)).join('/')
}

// Fails closed: a shared directory prefix in either direction counts as
// subtracting, even if a finer wildcard would keep the two apart.
export function negationSubtracts(negated, input) {
  const a = globPrefix(negated)
  const b = globPrefix(input)
  return (
    a === '' ||
    b === '' ||
    a === b ||
    b.startsWith(`${a}/`) ||
    a.startsWith(`${b}/`)
  )
}

// GitHub evaluates `paths:` in order and the last matching pattern wins, so a
// scan for one positive entry would read ['**', '!X'] as covering X.
// `covers` is each caller's own test for a positive entry.
export function filterCovers(paths, input, covers) {
  let selected = false
  for (const entry of paths) {
    if (entry.startsWith('!')) {
      if (negationSubtracts(entry.slice(1), input)) selected = false
    } else if (entry === '**' || covers(entry, input)) {
      selected = true
    }
  }
  return selected
}
