/**
 * Everything before a glob's first wildcard SEGMENT — the deepest path both a
 * cache pattern and a `paths:` entry can be compared on.
 *
 * `languages/typescript/packages/protect-ffi/crates/**` -> `languages/typescript/packages/protect-ffi/crates`
 * `languages/typescript/packages/protect-ffi/src/errors.ts` -> itself (no wildcard)
 */
export const globPrefix = (pattern) => {
  const segments = pattern.split('/')
  const at = segments.findIndex((segment) => /[*?[]/.test(segment))
  return (at === -1 ? segments : segments.slice(0, at)).join('/')
}

/**
 * Does one `paths:` entry cover everything an input pattern can match?
 *
 * Deliberately conservative: only a literal entry or a `**`-tailed one counts.
 * An entry with a wildcard in any earlier segment (a mid-path `*`, or a tail
 * like `*.ts`) is treated as covering nothing, so it fails loudly and gets a
 * matcher that understands it — the opposite
 * bias would be a false green, which here means an input nothing triggers on,
 * which is the defect these guards exist for.
 */
export function entryCovers(entry, input) {
  const prefix = globPrefix(entry)
  const tail = entry.slice(prefix.length).replace(/^\//, '')
  if (tail !== '' && tail !== '**') return false
  const target = globPrefix(input)
  return target === prefix || target.startsWith(`${prefix}/`)
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

// Fails open, for callers asking whether an input can still start a workflow:
// a file-type negation such as `!**.md` must not read as removing every input.
export function negationRemovesAll(negated, input) {
  const a = globPrefix(negated)
  const b = globPrefix(input)
  const rest = negated.slice(a.length).replace(/^\//, '')
  return rest === '**' && (a === '' || a === b || b.startsWith(`${a}/`))
}

// GitHub evaluates `paths:` in order and the last matching pattern wins, so a
// scan for one positive entry would read ['**', '!X'] as covering X.
// `covers` and `subtracts` are each caller's own tests for a positive and a
// negated entry.
export function filterCovers(
  paths,
  input,
  covers,
  subtracts = negationSubtracts,
) {
  let selected = false
  for (const entry of paths) {
    if (entry.startsWith('!')) {
      if (subtracts(entry.slice(1), input)) selected = false
    } else if (entry === '**' || covers(entry, input)) {
      selected = true
    }
  }
  return selected
}
