/**
 * What `config` on the edge entry actually requires (#812).
 *
 * The shipped skill and the package README both said `config` on
 * `@cipherstash/stack-supabase/wasm-inline` "must carry all four `CS_*`
 * values", because there is no `~/.cipherstash` to discover credentials from
 * on an edge runtime. That is true of exactly ONE of the three arms
 * `WasmClientConfig` accepts (`packages/stack/src/wasm-inline.ts`): the
 * access-key arm. On the `authStrategy` arm — the one an
 * `OidcFederationStrategy` takes, i.e. every identity-aware edge deployment —
 * `accessKey` is `never` and `workspaceCrn` is OPTIONAL, because a pre-built
 * strategy already carries the CRN. A reader who believed the docs would
 * either invent an access key they do not have, or conclude the edge entry
 * cannot do per-user encryption at all.
 *
 * The claim is a claim about the TYPE, so it is pinned at the type level: the
 * runtime never sees the difference until it tries to authenticate. Both arms
 * must type-check through `encryptedSupabase`'s own `config` option, not
 * merely through `WasmClientConfig` in isolation —
 * `EncryptedSupabaseWasmOptions` re-declares that field and could narrow it.
 *
 * The negative is the floor the docs SHOULD describe: `clientId` + `clientKey`
 * with neither an access key nor a strategy satisfies no arm.
 *
 * Runs under `pnpm --filter @cipherstash/stack-supabase test:types`.
 * `@cipherstash/stack/wasm-inline` has no `paths` entry in
 * `tsconfig.json`, so it resolves through the workspace `exports` map to
 * `packages/stack/dist/wasm-inline.d.ts` — build `@cipherstash/stack` first.
 */

import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import type {
  AccessKeyStrategy,
  OidcFederationStrategy,
  WasmClientConfig,
} from '@cipherstash/stack/wasm-inline'
import { describe, expectTypeOf, it } from 'vitest'
import type { SupabaseClientLike } from '../src/types.js'
import { encryptedSupabase } from '../src/wasm-inline.js'

declare const supabaseClient: SupabaseClientLike

/**
 * Strategy INSTANCES, not the classes. `config.authStrategy` takes a built
 * strategy (`OidcFederationStrategy.create(…)`), and both classes are
 * re-exported from `@cipherstash/stack/wasm-inline` precisely so an edge
 * consumer needs no separate `@cipherstash/auth` import.
 */
declare const oidc: OidcFederationStrategy
declare const accessKeyStrategy: AccessKeyStrategy

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
})

describe('the edge entry `config` accepts either auth arm', () => {
  it('accepts the access-key arm — the one the docs described', async () => {
    await encryptedSupabase(supabaseClient, {
      schemas: { users },
      config: {
        workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
        accessKey: 'CS_CLIENT_ACCESS_KEY',
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
    })
  })

  it('accepts the authStrategy arm with NO workspaceCrn and NO accessKey', async () => {
    await encryptedSupabase(supabaseClient, {
      schemas: { users },
      config: {
        authStrategy: oidc,
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
    })
  })

  it('accepts an AccessKeyStrategy instance on that same arm', async () => {
    await encryptedSupabase(supabaseClient, {
      schemas: { users },
      config: {
        authStrategy: accessKeyStrategy,
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
    })
  })

  it('still allows workspaceCrn alongside a strategy — optional, not banned', async () => {
    await encryptedSupabase(supabaseClient, {
      schemas: { users },
      config: {
        workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
        authStrategy: oidc,
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
    })
  })

  it('rejects clientId + clientKey alone — the genuine required floor', async () => {
    await encryptedSupabase(supabaseClient, {
      schemas: { users },
      // @ts-expect-error — no accessKey and no authStrategy satisfies no arm
      config: {
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
    })
  })

  it('rejects mixing an access key with a strategy', async () => {
    await encryptedSupabase(supabaseClient, {
      schemas: { users },
      // @ts-expect-error — `accessKey` is `never` on the strategy arm
      config: {
        workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
        accessKey: 'CS_CLIENT_ACCESS_KEY',
        authStrategy: oidc,
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
    })
  })

  /**
   * The positive control for the two `@ts-expect-error`s above. If
   * `EncryptedSupabaseWasmOptions['config']` ever widened to `unknown` or the
   * native `ClientConfig`, both directives would go unused and vitest's
   * typecheck would report THAT — but only if this file still says which type
   * is meant to be under test.
   */
  it('is `WasmClientConfig`, not the native optional ClientConfig', () => {
    expectTypeOf<
      Parameters<typeof encryptedSupabase<{ users: typeof users }>>[1]['config']
    >().toEqualTypeOf<WasmClientConfig>()
  })
})
