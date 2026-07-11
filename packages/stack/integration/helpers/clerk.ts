import { requireIntegrationEnv } from '@cipherstash/test-kit'
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
 * The federated identity is the Clerk machine (`CTS|CS|mch_…`), which is stable
 * across encrypt and decrypt — enough for the symmetric round-trip and the
 * no-context negative path. The cross-identity test needs a SECOND machine
 * token (a distinct `sub`) and remains a follow-up.
 *
 * The workspace named by `CS_WORKSPACE_CRN` must have this Clerk instance
 * registered on its OIDC-providers page, or `/api/authorise` rejects the token.
 */
export function clerkJwtProvider(): () => Promise<string> {
  requireIntegrationEnv(['clerk'])
  const machineSecretKey = process.env['CLERK_MACHINE_TOKEN'] as string

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
