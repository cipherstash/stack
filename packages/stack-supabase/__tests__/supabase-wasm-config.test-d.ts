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
 * The file has since grown a second claim about the same options object — that
 * `databaseUrl` cannot be passed at all. See the second `describe` for why
 * leaving the field out was not, on its own, enough to enforce that.
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

/**
 * `databaseUrl` is not merely ABSENT from the edge entry's options — it is
 * declared `?: never` (`src/wasm-inline.ts`), and the difference between those
 * two is the whole reason this block exists.
 *
 * Absence is enforced by excess-property checking alone, which fires on FRESH
 * object literals only. An options object assembled as a `const` and passed by
 * variable — which is what a Node → edge port actually holds, since the native
 * entry's options are typically built once and reused — loses freshness at the
 * declaration, carries no excess-property check at the call, and so
 * type-checked clean before reaching the runtime throw in
 * `makeEncryptedSupabase` (`src/create.ts`). The docs meanwhile claimed the
 * type checker enforced it.
 *
 * Same failure mode and same fix as `WasmClientConfig.eqlVersion?: never` in
 * `packages/stack/src/wasm-inline.ts`, whose comment describes exactly this
 * shared-config-const path; this is its sibling one package along.
 *
 * The runtime throw stays regardless — it is the backstop for plain JS, where
 * there is no type to consult. What is pinned here is the half a type CAN
 * enforce, in both the shapes a caller writes it in.
 */
describe('the edge entry refuses `databaseUrl`', () => {
  it('rejects it on a fresh object literal — the excess-property case', async () => {
    await encryptedSupabase(supabaseClient, {
      schemas: { users },
      config: {
        workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
        accessKey: 'CS_CLIENT_ACCESS_KEY',
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
      // @ts-expect-error — this entry carries no Postgres driver and cannot introspect
      databaseUrl: 'postgres://user:pass@localhost:5432/postgres',
    })
  })

  it('rejects it on a fresh object literal in the (url, key, options) form', async () => {
    await encryptedSupabase(
      'https://project.supabase.co',
      'SUPABASE_ANON_KEY',
      {
        schemas: { users },
        config: {
          workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
          accessKey: 'CS_CLIENT_ACCESS_KEY',
          clientId: 'CS_CLIENT_ID',
          clientKey: 'CS_CLIENT_KEY',
        },
        // @ts-expect-error — this entry carries no Postgres driver and cannot introspect
        databaseUrl: 'postgres://user:pass@localhost:5432/postgres',
      },
    )
  })

  it('rejects it when the options are passed by variable, not as a literal', async () => {
    // Declared, not inlined: the literal's freshness is spent here, so the call
    // below gets no excess-property check. This is the shape the `?: never` is
    // for — without it this call type-checks and fails at run time instead.
    const options = {
      schemas: { users },
      config: {
        workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
        accessKey: 'CS_CLIENT_ACCESS_KEY',
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
      databaseUrl: 'postgres://user:pass@localhost:5432/postgres',
    }

    await encryptedSupabase(
      supabaseClient,
      // @ts-expect-error — `databaseUrl?: never` is what rejects this; absence would not
      options,
    )
  })

  it('rejects it by variable in the (url, key, options) form too', async () => {
    const options = {
      schemas: { users },
      config: {
        workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
        accessKey: 'CS_CLIENT_ACCESS_KEY',
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
      databaseUrl: 'postgres://user:pass@localhost:5432/postgres',
    }

    await encryptedSupabase(
      'https://project.supabase.co',
      'SUPABASE_ANON_KEY',
      // @ts-expect-error — `databaseUrl?: never` is what rejects this; absence would not
      options,
    )
  })

  /**
   * The positive control for the four `@ts-expect-error`s above: the same
   * by-variable call, with the offending field removed, must still compile. A
   * `?: never` that accidentally poisoned the whole options type would make
   * every call above fail for the wrong reason and this one fail outright.
   */
  it('still accepts the same options object once `databaseUrl` is dropped', async () => {
    const options = {
      schemas: { users },
      config: {
        workspaceCrn: 'crn:ap-southeast-2.aws:my-workspace-id',
        accessKey: 'CS_CLIENT_ACCESS_KEY',
        clientId: 'CS_CLIENT_ID',
        clientKey: 'CS_CLIENT_KEY',
      },
    }

    await encryptedSupabase(supabaseClient, options)
  })
})
