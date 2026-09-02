# @cipherstash/nextjs

## 4.2.0

### Minor Changes

- d3efdbd: Report what the CipherStash token service actually said when it refuses a token.

  `getCtsToken()` reported a non-2xx response as `Failed to fetch CTS token: ` and
  nothing else. It read `statusText`, which is the empty string over HTTP/2 — so
  the message ended at the colon — and it discarded the response body, taking any
  refusal code with it. A billing refusal was indistinguishable from a bad token,
  and the accompanying log said "contact support", which is the wrong advice for
  an organisation that needs to upgrade a plan.

  The failure now names the status and quotes what the service returned, and the
  refusal code is surfaced on a new optional `authCode` field of
  `GetCtsTokenResponse` — `USAGE_LIMIT_EXCEEDED` for an organisation over its
  allowance, `ORG_NOT_PROVISIONED` for one not registered with the usage system.
  Both are terminal: retrying cannot clear either. Unknown `402` codes are
  declined so a future payment-required response does not inherit the wrong
  classification.

  The body is read as text exactly once and then parsed defensively, never with
  `response.json()`. The two shapes are not the same shape: a `402` is JSON, while
  every other failure from this endpoint is `text/plain` (a `401` is the bare
  string `Authorization failed: InvalidToken`), and `.json()` on one of those
  throws a `SyntaxError` that replaces the real failure with a parse error. A
  response that is not a recognisable CipherStash refusal — a gateway or WAF
  answering in front of the service — still reports its status and body rather
  than being reported as a billing problem it is not.

  This package does not depend on `@cipherstash/stack`, so it carries the code
  rather than a copy of that package's remedy text — look the remedy up from
  `authCode` if you need to render one.

## 4.1.2

### Patch Changes

- 7387414: Correct the published package metadata to reference `@cipherstash/stack`
  instead of the removed `@cipherstash/protect` package. The package now also
  ships with its own source typecheck command and keeps its Vitest mock typing
  compatible with the repository-pinned test runner.

## 4.1.1

### Patch Changes

- aa9c4b1: Documentation: refresh package READMEs after the protectjs → stack repository rename. Fixed repository and license links, replaced dead in-repo docs links with cipherstash.com/docs URLs, rewrote the incorrect @cipherstash/nextjs README, and added guidance pointing new projects to @cipherstash/stack.

## 4.1.0

### Minor Changes

- 1535259: Remove node api calls which are incompatible with Next.js middleware.

## 4.0.0

### Major Changes

- 95c891d: Implemented CipherStash CRN in favor of workspace ID.

  - Replaces the environment variable `CS_WORKSPACE_ID` with `CS_WORKSPACE_CRN`
  - Replaces `workspace_id` with `workspace_crn` in the `cipherstash.toml` file

## 3.2.0

### Minor Changes

- 9377b47: Updated versions to address Next.js CVE.

## 3.1.0

### Minor Changes

- a564f21: Bumped versions of dependencies to address CWE-346.

## 3.0.0

### Major Changes

- 02dc980: Support configuration from environment variables or toml config.

## 2.1.0

### Minor Changes

- 5a34e76: Rebranded logging context and fixed tests.

## 2.0.0

### Major Changes

- 76599e5: Rebrand jseql to protect.

## 1.2.0

### Minor Changes

- 3cb97c2: Added an optional argument to getCtsToken to fetch a new CTS token.

## 1.1.0

### Minor Changes

- d0f5dd9: Enforced a check for the subject claims before setting cts session.

## 1.0.0

### Major Changes

- 24f0a72: Implemented better error handling for fetching CTS tokens and accessing them in the Next.js application.

## 0.12.0

### Minor Changes

- 14c0279: Fixed optional response argument getting called in setCtsToken.

## 0.11.0

### Minor Changes

- ebc23ba: Added support for optional next response in generic jseql middleware functions.

## 0.10.0

### Minor Changes

- 7d0fac0: Implemented a generic Next.js jseql middleware.

## 0.9.0

### Minor Changes

- e885975: Fixed improper use of throwing errors, and log with jseql logger.

## 0.8.0

### Minor Changes

- eeaec18: Implemented typing and import synatx for es6.

## 0.7.0

### Minor Changes

- 7b8ec52: Implement packageless logging framework.

## 0.6.0

### Minor Changes

- 7480cfd: Fixed node:util package bundling.

## 0.5.0

### Minor Changes

- c0123be: Replaced logtape with native node debuglog.

## 0.4.0

### Minor Changes

- 3bb4a10: Cleared session cookies when a user has logged out.

## 0.3.0

### Minor Changes

- 9a3132c: Fixed the logtape peer dependency version.

## 0.2.0

### Minor Changes

- 80ee5af: Fixed bugs when implmenting the lock context with CTS v2 tokens.

## 0.1.0

### Minor Changes

- fbb2bcb: Released jseql clerk middleware.
