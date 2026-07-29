type LikeToken = { value: string; wildcard: boolean }

export type LikeNeedle = {
  needle: string
  hasUnsupportedWildcard: boolean
}

/**
 * Reduce a SQL LIKE pattern to the literal needle used by encrypted fuzzy
 * matching. Only unescaped leading/trailing `%` tokens are approximable;
 * escaped metacharacters remain literal and every other wildcard is reported.
 *
 * A trailing lone backslash (which Postgres itself rejects, "LIKE pattern must
 * not end with escape character") is deliberately kept as a literal backslash
 * rather than throwing: the needle is only an approximation feeding encrypted
 * fuzzy matching, and the plaintext `like` path never reaches here.
 */
export function parseLikeNeedle(pattern: string): LikeNeedle {
  const tokens: LikeToken[] = []
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i]
    if (char === '\\' && i + 1 < pattern.length) {
      tokens.push({ value: pattern[++i], wildcard: false })
    } else {
      tokens.push({
        value: char,
        wildcard: char === '%' || char === '_',
      })
    }
  }

  while (tokens[0]?.wildcard && tokens[0].value === '%') tokens.shift()
  while (
    tokens[tokens.length - 1]?.wildcard &&
    tokens[tokens.length - 1]?.value === '%'
  ) {
    tokens.pop()
  }

  return {
    needle: tokens.map((token) => token.value).join(''),
    hasUnsupportedWildcard: tokens.some((token) => token.wildcard),
  }
}
