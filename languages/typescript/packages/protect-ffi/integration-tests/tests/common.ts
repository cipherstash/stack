import type {
  EncryptConfig,
  EncryptedPayload,
  EncryptedQuery,
  EncryptedScalar,
  EncryptedSteVec,
  EncryptedV3Query,
} from '../../lib/index.cjs'

// Everything encrypt / encryptBulk ({@link EncryptedPayload}) and
// encryptQuery / encryptQueryBulk ({@link EncryptedQuery} /
// {@link EncryptedV3Query}) can return — these helpers accept any of those
// dual-format shapes (including the bare v3 selector string) and narrow to
// the v2 shapes the tests assert on.
type AnyEncrypted = EncryptedPayload | EncryptedQuery | EncryptedV3Query

function formDiscriminator(payload: AnyEncrypted): unknown {
  return typeof payload === 'object' && payload !== null && 'k' in payload
    ? payload.k
    : undefined
}

export function assertSteVec(
  payload: AnyEncrypted,
): asserts payload is EncryptedSteVec {
  const k = formDiscriminator(payload)
  if (k !== 'sv') {
    throw new Error(`expected k:"sv" payload, got k:"${String(k)}"`)
  }
}

export function assertScalar(
  payload: AnyEncrypted,
): asserts payload is EncryptedScalar {
  const k = formDiscriminator(payload)
  if (k !== 'ct') {
    throw new Error(`expected k:"ct" payload, got k:"${String(k)}"`)
  }
}

type WireKeys<T> = Extract<keyof T, string>

/**
 * Builds the exact top-level wire key set of an EQL v3 payload type, making
 * the config -> eql_v3 domain mapping load-bearing in two legs:
 *
 * - Compile time: the key list must name every key of `T` (a missing key
 *   collapses the parameter type into an error tuple) and may not name
 *   anything that is not a key of `T` — so tsc fails if a test's expected
 *   key set drifts from the vendored eql_v3 domain type.
 * - Runtime: the returned sorted array is compared with exact equality
 *   against `Object.keys(payload).sort()`, so a payload that selected a
 *   richer domain (extra keys) or a poorer one (missing keys) both fail.
 */
export function v3WireKeys<T>() {
  return <const K extends readonly WireKeys<T>[]>(
    ...keys: WireKeys<T> extends K[number]
      ? K
      : [`missing wire key: ${Exclude<WireKeys<T>, K[number]>}`]
  ): string[] => [...keys].sort()
}

export const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'string',
        indexes: {
          ore: {},
          match: {},
          unique: {},
        },
      },
      score: {
        cast_as: 'bigint',
        indexes: { ore: {} },
      },
      score_float: {
        cast_as: 'number',
        indexes: { ore: {} },
      },
      profile: {
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'users/profile' } },
      },
    },
  },
}

// Scalar-only config used to retain explicit coverage of the EQL v2 default.
// A mixed config containing SteVec defaults to v3 under client 0.42.
export const scalarConfig: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      email: {
        cast_as: 'string',
        indexes: {
          ore: {},
          match: {},
          unique: {},
        },
      },
      score: {
        cast_as: 'bigint',
        indexes: { ore: {} },
      },
      score_float: {
        cast_as: 'number',
        indexes: { ore: {} },
      },
    },
  },
}

// A single JSON column with no indexes (will be treated as an opaque blob)
export const jsonOpaque: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      profile: {
        cast_as: 'json',
        indexes: {},
      },
    },
  },
}

// Config with a date and a timestamp column for testing JS Date round-trips
export const datesConfig: EncryptConfig = {
  v: 1,
  tables: {
    events: {
      occurred_on: {
        cast_as: 'date',
      },
      occurred_at: {
        cast_as: 'timestamp',
      },
    },
  },
}

// A single JSON column with an ste_vec index.
//
// Client 0.42 emits SteVec only in EQL v3, whose JSON domain supports the
// `compat` CLLW-OPE (`op`) ordering term.
export const jsonSteVec: EncryptConfig = {
  v: 1,
  tables: {
    users: {
      profile: {
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'users/profile', mode: 'compat' } },
      },
    },
  },
}
