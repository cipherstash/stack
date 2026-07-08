# @cipherstash/nextjs

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
