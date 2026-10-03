/**
 * A small evaluator for the GitHub Actions expression subset used by job `if:`.
 *
 * Extracted from `workflow-dispatch-job-conditions.test.mjs` when a second
 * guard needed it: `eql-release-assets.test.mjs` walks the release job graph
 * through the same conditions. Two evaluators would be two opinions about
 * what a condition means, and the guard that disagreed with GitHub would be the
 * one nobody noticed.
 *
 * The grammar is small on purpose and it THROWS on anything outside it — a
 * condition this module cannot reason about fails loudly rather than being
 * waved through, because "the evaluator did not understand it" and "the job
 * runs" must not produce the same green.
 */

export class UnsupportedExpression extends Error {}

/**
 * GitHub's loose equality: "if the types do not match, GitHub coerces the type
 * to a number", with null -> 0, booleans -> 0/1, non-numeric strings and
 * objects -> NaN. That coercion is why the original condition failed silently
 * rather than erroring — `null == 'cipherstash/stack'` is `0 == NaN`, false.
 */
function toNumber(value) {
  if (value === null || value === undefined) return 0
  if (typeof value === 'boolean') return value ? 1 : 0
  if (typeof value === 'number') return value
  if (typeof value === 'string') {
    if (value.trim() === '') return 0
    return Number(value)
  }
  return Number.NaN
}

export function looseEquals(a, b) {
  // GitHub compares strings case-insensitively.
  if (typeof a === 'string' && typeof b === 'string') {
    return a.toLowerCase() === b.toLowerCase()
  }
  if (typeof a === 'boolean' && typeof b === 'boolean') return a === b
  const [x, y] = [toNumber(a), toNumber(b)]
  return Number.isNaN(x) || Number.isNaN(y) ? false : x === y
}

/** GitHub truthiness: null, false, 0 and the empty string are false. */
function truthy(value) {
  if (value === null || value === undefined) return false
  if (typeof value === 'string') return value !== ''
  if (typeof value === 'number') return value !== 0
  if (typeof value === 'boolean') return value
  return true
}

function tokenize(expression) {
  const tokens = []
  let i = 0
  while (i < expression.length) {
    const ch = expression[i]
    if (/\s/.test(ch)) {
      i++
      continue
    }
    if (ch === "'") {
      // `''` is GitHub's escape for a literal quote inside a string.
      let value = ''
      i++
      while (i < expression.length) {
        if (expression[i] === "'") {
          if (expression[i + 1] === "'") {
            value += "'"
            i += 2
            continue
          }
          i++
          break
        }
        value += expression[i]
        i++
      }
      tokens.push({ type: 'string', value })
      continue
    }
    const two = expression.slice(i, i + 2)
    if (two === '==' || two === '!=' || two === '&&' || two === '||') {
      tokens.push({ type: 'operator', value: two })
      i += 2
      continue
    }
    if (ch === '(' || ch === ')' || ch === '!') {
      tokens.push({ type: 'operator', value: ch })
      i++
      continue
    }
    const path = /^[A-Za-z_][A-Za-z0-9_.-]*/.exec(expression.slice(i))
    if (path) {
      tokens.push({ type: 'path', value: path[0] })
      i += path[0].length
      continue
    }
    const number = /^\d+(\.\d+)?/.exec(expression.slice(i))
    if (number) {
      tokens.push({ type: 'number', value: Number(number[0]) })
      i += number[0].length
      continue
    }
    throw new UnsupportedExpression(
      `unexpected character ${JSON.stringify(ch)} at offset ${i}`,
    )
  }
  return tokens
}

/** Walk a dotted path; a missing property yields null, as GitHub does. */
function lookup(path, context) {
  let current = context
  for (const segment of path.split('.')) {
    if (current === null || typeof current !== 'object') return null
    current = segment in current ? current[segment] : null
  }
  return current === undefined ? null : current
}

/**
 * The only status functions this evaluator will accept, and only in their
 * zero-argument form.
 *
 * `always()` is total: it is true on every event, for every job, whatever its
 * `needs:` reported. So it can be modelled exactly rather than guessed at,
 * which is the bar the rest of this file sets. An aggregator job — EQL's
 * `ci-required`, the single required status check its merge queue references —
 * cannot be written without it, and refusing the whole grammar would have meant
 * either no such job in a dispatchable workflow, or this guard skipping the
 * workflow that contains one.
 *
 * `cancelled()` is a fact about the run, not about any job, so it comes from
 * the caller's `run` argument and is false unless that says `cancelled: true`.
 *
 * Everything else still throws. `success()` and `failure()` depend on the
 * results of the whole `needs:` chain, which the contexts here do not carry,
 * and `contains()` / `startsWith` take arguments the parser below deliberately
 * cannot evaluate.
 */
const SUPPORTED_FUNCTIONS = new Map([
  ['always', () => true],
  ['cancelled', (run) => run.cancelled === true],
])

/**
 * Recursive descent over `|| && ! == != ()`, string / number / boolean
 * literals, context paths, and the zero-argument functions in
 * `SUPPORTED_FUNCTIONS`. Any other call throws: guessing at a function's
 * verdict is worse than refusing it, because "the evaluator did not understand
 * it" and "the job runs" must not produce the same green.
 */
function evaluate(expression, context, run) {
  const tokens = tokenize(expression)
  let position = 0

  const peek = () => tokens[position]
  const eat = (value) => {
    if (peek()?.value === value) {
      position++
      return true
    }
    return false
  }

  const parsePrimary = () => {
    const token = peek()
    if (!token) throw new UnsupportedExpression('unexpected end of expression')
    if (eat('(')) {
      const value = parseOr()
      if (!eat(')')) throw new UnsupportedExpression('unbalanced parentheses')
      return value
    }
    position++
    if (token.type === 'string' || token.type === 'number') return token.value
    if (token.type === 'path') {
      if (peek()?.value === '(') {
        const fn = SUPPORTED_FUNCTIONS.get(token.value)
        // Zero-argument only: `(` must be followed directly by `)`. A call with
        // arguments falls through to the throw, even for a supported name.
        if (fn && tokens[position + 1]?.value === ')') {
          position += 2
          return fn(run)
        }
        throw new UnsupportedExpression(
          `function call ${token.value}() is not understood`,
        )
      }
      if (token.value === 'true') return true
      if (token.value === 'false') return false
      if (token.value === 'null') return null
      return lookup(token.value, context)
    }
    throw new UnsupportedExpression(`unexpected token ${token.value}`)
  }

  const parseUnary = () => {
    if (eat('!')) return !truthy(parseUnary())
    return parsePrimary()
  }

  const parseEquality = () => {
    let left = parseUnary()
    for (;;) {
      if (eat('==')) left = looseEquals(left, parseUnary())
      else if (eat('!=')) left = !looseEquals(left, parseUnary())
      else return left
    }
  }

  const parseAnd = () => {
    let left = parseEquality()
    while (eat('&&')) {
      const right = parseEquality()
      left = truthy(left) ? right : left
    }
    return left
  }

  function parseOr() {
    let left = parseAnd()
    while (eat('||')) {
      const right = parseAnd()
      left = truthy(left) ? left : right
    }
    return left
  }

  const value = parseOr()
  if (position !== tokens.length) {
    throw new UnsupportedExpression(
      `trailing input from token ${position}: ${tokens
        .slice(position)
        .map((token) => token.value)
        .join(' ')}`,
    )
  }
  return truthy(value)
}

/** Strip the optional `${{ … }}` wrapper GitHub allows around a condition. */
export function unwrap(condition) {
  const trimmed = String(condition).trim()
  const match = /^\$\{\{([\s\S]*)\}\}$/.exec(trimmed)
  return (match ? match[1] : trimmed).trim()
}

/** `context` is `{ github, needs, vars }`; `run` is `{ cancelled }`. */
export function runsWhen(condition, context, run = {}) {
  return evaluate(unwrap(condition), context, run)
}

/** `${{ body }}`, as a parsed workflow holds it, without a JS placeholder lint. */
export const expr = (body) => `\${{ ${body} }}`
