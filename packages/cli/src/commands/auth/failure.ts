/**
 * Rendering for an `@cipherstash/auth` `AuthFailure` — the shape every CTS
 * interaction in this CLI returns on the failure arm.
 *
 * Two things were being dropped at every call site.
 *
 * **`help`.** Every `AuthError` in stack-auth carries `miette` help — the
 * sentence that says what to actually do — and `miette` help is not part of an
 * error's `Display`. `failure.error.message` therefore prints the diagnosis
 * without the remedy: "Not authenticated" with no mention of `stash auth
 * login`, "Insufficient balance. Please upgrade your plan." with no mention of
 * where a plan is upgraded.
 *
 * **The distinction between a fixable failure and a billing one.** The default
 * hint on these paths is "run `stash auth login` and try again", which is
 * correct for a stale session and actively misleading for an organisation over
 * its usage limit: re-authenticating cannot mint a credential CTS is refusing
 * on billing grounds, so the user burns a login round trip and lands back here.
 */

/**
 * The `AuthFailure` fields this module reads.
 *
 * Structural rather than an import of `AuthFailure` itself so this renderer
 * remains tolerant of future auth codes.
 */
type RenderableFailure = {
  type?: string
  error: { message: string }
  help?: string
  url?: string
}

/**
 * Account refusals for which another login cannot help. Their guidance comes
 * from stack-auth's `help` and `url`; the CLI owns no copy of that prose.
 */
const TERMINAL_AUTH_CODES: ReadonlySet<string> = new Set([
  'USAGE_LIMIT_EXCEEDED',
  'ORG_NOT_PROVISIONED',
])

/**
 * The `--json` `code` to report for each terminal refusal, replacing whatever
 * generic code the call site would otherwise use.
 *
 * `code` is the only machine-readable field on the error envelope, so it has to
 * agree with the hint: reporting `session_invalid` while the hint says "logging
 * in again will not clear this" tells an agent to re-login and land straight
 * back here. `__tests__/failure.test.ts` asserts the terminal set and CLI code
 * mapping stay in step.
 */
const TERMINAL_CLI_CODES: ReadonlyMap<string, string> = new Map([
  ['USAGE_LIMIT_EXCEEDED', 'usage_limit_exceeded'],
  ['ORG_NOT_PROVISIONED', 'org_not_provisioned'],
])

/**
 * Sentence-ending punctuation, for deciding whether the joiner below owes the
 * diagnosis a full stop.
 *
 * `.` alone was not enough: a CTS diagnosis is a sentence written by whoever
 * raised it, and `'Upgrade now!'` came out as `'Upgrade now!. See the
 * dashboard.'` A question mark has the same problem.
 *
 * This is local presentation logic for the CLI. Stack preserves diagnostic
 * fields separately and does not join its message with help text.
 */
const TERMINAL_PUNCTUATION = /[.!?]$/

/**
 * What went wrong, plus the remedy stack-auth attached to it.
 *
 * Falls back to the bare message when the failure carries no help, so nothing
 * gains a trailing separator it did not have before — and to the bare help when
 * there is no message, so the separator is not the only thing that survives.
 */
export function authFailureMessage(failure: RenderableFailure): string {
  const { message } = failure.error
  if (!failure.help) return message
  if (!message) return failure.help
  return TERMINAL_PUNCTUATION.test(message)
    ? `${message} ${failure.help}`
    : `${message}. ${failure.help}`
}

/**
 * The hint to show for this failure — the caller's default, unless the failure
 * is one no retry can clear.
 *
 * `type` is `string | undefined` (see {@link RenderableFailure}), and the
 * lookup has to survive both. It is written as a `?? ''` key rather than
 * `failure.type && …` because that form short-circuits an EMPTY type to `''`,
 * which `??` does not rescue — `stash env` then built a `MintError` with
 * `hint: ''` and its own `if (failure.hint)` guard swallowed the hint whole.
 *
 * @param fallback the hint that applies to an ordinary auth failure
 */
export function authFailureHint(
  failure: RenderableFailure,
  fallback?: string,
): string | undefined {
  if (!TERMINAL_AUTH_CODES.has(failure.type ?? '')) return fallback
  return [failure.help, failure.url].filter(Boolean).join(' ') || undefined
}

/**
 * The `--json` `code` to report for this failure — the caller's own, unless the
 * failure is one no retry can clear.
 *
 * Pairs with {@link authFailureHint}: whenever that returns a terminal remedy,
 * this returns the matching terminal code, so the stream's machine-readable
 * field and its prose cannot disagree about whether re-login is worth trying.
 *
 * @param fallback the code that applies to an ordinary auth failure
 */
export function authFailureCliCode(
  failure: RenderableFailure,
  fallback: string,
): string {
  return TERMINAL_CLI_CODES.get(failure.type ?? '') ?? fallback
}
