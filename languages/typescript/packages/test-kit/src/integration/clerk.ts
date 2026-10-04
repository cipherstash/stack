import { createClerkClient } from '@clerk/backend'

/**
 * A `getJwt` provider for `OidcFederationStrategy` that mints a fresh Clerk
 * machine-to-machine token (JWT) on demand.
 *
 * Why this instead of a stored `USER_JWT`: the strategy re-invokes `getJwt` on
 * every (re-)federation and CTS issues no refresh token, so a short-lived,
 * freshly-minted token self-heals on expiry — nothing long-lived is ever kept
 * in an env var or a CI secret. The only secret is `CLERK_MACHINE_TOKEN`, a
 * rotatable machine key.
 *
 * The federated identity is the Clerk machine (`CTS|CS|mch_…`), stable across
 * encrypt and decrypt. Pass a different `tokenEnvVar` (e.g. a second machine's
 * `CLERK_MACHINE_TOKEN_B`) to federate as a DISTINCT identity — that is what the
 * cross-identity test uses to prove a row sealed under one machine does not
 * decrypt under another.
 *
 * The workspace named by `CS_WORKSPACE_CRN` must have this Clerk instance
 * registered on its OIDC-providers page, or `/api/authorise` rejects the token.
 */
export function clerkJwtProvider(
  tokenEnvVar = 'CLERK_MACHINE_TOKEN',
): () => Promise<string> {
  const machineSecretKey = process.env[tokenEnvVar]
  if (!machineSecretKey) {
    throw new Error(
      `Integration suite cannot run — missing ${tokenEnvVar} (a Clerk machine ` +
        'secret key, ak_...). Its Clerk instance must be registered on the ' +
        'CS_WORKSPACE_CRN workspace OIDC-providers page. This suite FAILS rather ' +
        'than skips: a green skip would hide a real regression.',
    )
  }

  // `createToken` authenticates with `machineSecretKey`; `createClerkClient`
  // still wants a `secretKey` string at construction that this path never uses.
  const clerk = createClerkClient({
    secretKey: process.env['CLERK_SECRET_KEY'] ?? 'sk_test_placeholder',
  })

  return async () => {
    const m2m = await clerk.m2m.createToken({
      machineSecretKey,
      tokenFormat: 'jwt',
      secondsUntilExpiration: 300,
    })
    if (typeof m2m.token !== 'string') {
      throw new Error(
        'Clerk M2M createToken did not return a JWT — enable the JWT token format for the machine in the Clerk Dashboard.',
      )
    }
    return m2m.token
  }
}
