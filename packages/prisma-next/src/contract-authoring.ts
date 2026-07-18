/**
 * Authoring contributions for the cipherstash extension.
 *
 * ## v3: one concrete constructor per exposed domain
 *
 * Every exposed v3 domain (the catalog minus the authoring-unexposed
 * `*_ord_ore` variants) gets exactly one argument-less PSL constructor,
 * derived 1:1 from `EXPOSED_DOMAIN_ENTRIES`:
 *
 *   `cipherstash.TextSearch` → codec
 *   `cipherstash/eql-v3/eql_v3_text_search@1`, native type
 *   `public.eql_v3_text_search`, static
 *   `typeParams: { castAs, capabilities }`.
 *
 * There are NO options: the constructor IS the capability set. The name is
 * the mechanical PascalCase `<Stem><Suffix>` transform of the bare domain with
 * its `eql_v3_` prefix stripped (`eql_v3_bigint_ord` → `BigIntOrd`);
 * the codec id keeps the registry key VERBATIM (never name-transformed).
 *
 * ### Static typeParams — confirmed framework shape (Step 0)
 *
 * `AuthoringStorageTypeTemplate.typeParams` is
 * `Record<string, AuthoringTemplateValue>`, and `AuthoringTemplateValue`
 * admits plain literals, arrays, and nested plain objects alongside
 * `AuthoringArgRef` nodes (framework-components 0.14,
 * `framework-authoring.d.ts`). `resolveAuthoringTemplateValue` deep-walks
 * objects and passes every non-`{ kind: 'arg' }` leaf through verbatim, so
 * the static `{ castAs, capabilities }` block below lowers to itself — no
 * `{ kind: 'literal' }` wrapper exists or is needed.
 *
 * ## v2: legacy `*V2` aliases
 *
 * The six pre-existing v2 constructors survive verbatim under `*V2` names
 * (`EncryptedStringV2`, …): same optional-object argument (all search-mode
 * flags default to `true` — searchable encryption is the legitimate default;
 * users opt out explicitly), same `cipherstash/*@1` codec ids, same
 * `eql_v2_encrypted` native type.
 *
 * The same descriptors lower a PSL field-type expression and the matching TS
 * factory (see `./exports/column-types`) to an identical
 * `ColumnTypeDescriptor`, so PSL- and TS-authored contracts emit
 * byte-identical `contract.json`.
 */

import type { QueryCapabilities } from '@cipherstash/stack/eql/v3'
import type {
  AuthoringTypeConstructorDescriptor,
  AuthoringTypeNamespace,
} from '@prisma-next/framework-components/authoring'
import {
  CIPHERSTASH_BIGINT_CODEC_ID,
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_DATE_CODEC_ID,
  CIPHERSTASH_DOUBLE_CODEC_ID,
  CIPHERSTASH_JSON_CODEC_ID,
  CIPHERSTASH_STRING_CODEC_ID,
  EQL_V2_ENCRYPTED_TYPE,
} from './extension-metadata/constants'
import { EXPOSED_DOMAIN_ENTRIES, type V3DomainMeta } from './v3/catalog'

// The stem of a bare domain maps to a JS-friendly display label; the suffix
// after the first `_` names the capability tier. `bigint` deliberately renders
// as `BigInt` (capital I) while `smallint` stays `Smallint` — this table is the
// single source for both PSL (`Encrypted…`) and TS (`encrypted…`) names.
const STEM_LABEL: Record<string, string> = {
  text: 'Text',
  integer: 'Integer',
  smallint: 'Smallint',
  bigint: 'BigInt',
  numeric: 'Numeric',
  real: 'Real',
  double: 'Double',
  date: 'Date',
  timestamp: 'Timestamp',
  boolean: 'Boolean',
  json: 'Json',
}
const SUFFIX_LABEL: Record<string, string> = {
  '': '',
  eq: 'Eq',
  ord: 'Ord',
  match: 'Match',
  search: 'Search',
}

const EQL_V3_DOMAIN_PREFIX = 'eql_v3_'

function coreName(bareDomain: string): string {
  // Every GA domain is `eql_v3_`-prefixed; a bare domain without it means the
  // registry drifted under us — fail loudly rather than emit a wrong name.
  if (!bareDomain.startsWith(EQL_V3_DOMAIN_PREFIX)) {
    throw new Error(
      `contract-authoring: exposed domain "${bareDomain}" lacks the "${EQL_V3_DOMAIN_PREFIX}" prefix — registry drift.`,
    )
  }
  const core = bareDomain.slice(EQL_V3_DOMAIN_PREFIX.length)
  const i = core.indexOf('_')
  const stem = i === -1 ? core : core.slice(0, i)
  const suffix = i === -1 ? '' : core.slice(i + 1)
  const stemLabel = STEM_LABEL[stem]
  const suffixLabel = SUFFIX_LABEL[suffix]
  if (stemLabel === undefined || suffixLabel === undefined) {
    throw new Error(
      `contract-authoring: cannot name exposed domain "${bareDomain}" — extend STEM_LABEL/SUFFIX_LABEL.`,
    )
  }
  return `${stemLabel}${suffixLabel}`
}

/**
 * `eql_v3_text_search` → `TextSearch`, `eql_v3_bigint_ord` → `BigIntOrd`.
 *
 * The `cipherstash.` PSL namespace already disambiguates, so the constructor
 * names drop the `Encrypted` prefix to line up with the stack / Drizzle
 * `types.*` catalog (`types.TextSearch`, `types.BigintOrd`, …). The v2
 * constructors keep their `*V2` names; the runtime envelope classes
 * (`EncryptedString`, `EncryptedBoolean`, …) are a separate surface and are
 * unchanged.
 */
export function v3PascalName(bareDomain: string): string {
  return coreName(bareDomain)
}
/**
 * `eql_v3_text_search` → `textSearch`, `eql_v3_bigint_ord` → `bigIntOrd`.
 *
 * Kept in lockstep with {@link v3PascalName} — the camelCase TS-authoring
 * factory name is the PSL constructor name with a lowercased first letter
 * (a property test enforces the two agree modulo first-letter case).
 */
export function v3CamelName(bareDomain: string): string {
  const core = coreName(bareDomain)
  return `${core.charAt(0).toLowerCase()}${core.slice(1)}`
}

/**
 * Re-shape the catalog's `QueryCapabilities` as an `AuthoringTemplateValue`
 * object. Explicit construction (rather than passing the catalog object
 * through) keeps the optional `searchableJson` slot out of the template when
 * the domain doesn't carry it, so non-JSON domains lower to exactly the three
 * boolean flags.
 */
function capabilitiesTemplate(
  capabilities: QueryCapabilities,
): Record<string, boolean> {
  return {
    equality: capabilities.equality,
    orderAndRange: capabilities.orderAndRange,
    freeTextSearch: capabilities.freeTextSearch,
    ...(capabilities.searchableJson !== undefined
      ? { searchableJson: capabilities.searchableJson }
      : {}),
  }
}

function v3Constructor(
  codecId: string,
  meta: V3DomainMeta,
): AuthoringTypeConstructorDescriptor {
  return {
    kind: 'typeConstructor',
    args: [],
    output: {
      codecId,
      nativeType: meta.nativeType,
      // Static, not `{ kind: 'arg' }`: there are no options — the constructor
      // IS the capability set (see "Static typeParams" in the header).
      typeParams: {
        castAs: meta.castAs,
        capabilities: capabilitiesTemplate(meta.capabilities),
      },
    },
  }
}

// --- v2 legacy aliases (verbatim pre-rename v2 outputs, now keyed *V2) ---

const encryptedStringV2 = {
  kind: 'typeConstructor',
  args: [
    {
      kind: 'object',
      name: 'options',
      optional: true,
      properties: {
        equality: { kind: 'boolean', optional: true },
        freeTextSearch: { kind: 'boolean', optional: true },
        orderAndRange: { kind: 'boolean', optional: true },
      },
    },
  ],
  output: {
    codecId: CIPHERSTASH_STRING_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: {
        kind: 'arg',
        index: 0,
        path: ['equality'],
        default: true,
      },
      freeTextSearch: {
        kind: 'arg',
        index: 0,
        path: ['freeTextSearch'],
        default: true,
      },
      orderAndRange: {
        kind: 'arg',
        index: 0,
        path: ['orderAndRange'],
        default: true,
      },
    },
  },
} as const satisfies AuthoringTypeConstructorDescriptor

const encryptedDoubleV2 = {
  kind: 'typeConstructor',
  args: [
    {
      kind: 'object',
      name: 'options',
      optional: true,
      properties: {
        equality: { kind: 'boolean', optional: true },
        orderAndRange: { kind: 'boolean', optional: true },
      },
    },
  ],
  output: {
    codecId: CIPHERSTASH_DOUBLE_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: {
        kind: 'arg',
        index: 0,
        path: ['equality'],
        default: true,
      },
      orderAndRange: {
        kind: 'arg',
        index: 0,
        path: ['orderAndRange'],
        default: true,
      },
    },
  },
} as const satisfies AuthoringTypeConstructorDescriptor

const encryptedBigIntV2 = {
  kind: 'typeConstructor',
  args: [
    {
      kind: 'object',
      name: 'options',
      optional: true,
      properties: {
        equality: { kind: 'boolean', optional: true },
        orderAndRange: { kind: 'boolean', optional: true },
      },
    },
  ],
  output: {
    codecId: CIPHERSTASH_BIGINT_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: {
        kind: 'arg',
        index: 0,
        path: ['equality'],
        default: true,
      },
      orderAndRange: {
        kind: 'arg',
        index: 0,
        path: ['orderAndRange'],
        default: true,
      },
    },
  },
} as const satisfies AuthoringTypeConstructorDescriptor

const encryptedDateV2 = {
  kind: 'typeConstructor',
  args: [
    {
      kind: 'object',
      name: 'options',
      optional: true,
      properties: {
        equality: { kind: 'boolean', optional: true },
        orderAndRange: { kind: 'boolean', optional: true },
      },
    },
  ],
  output: {
    codecId: CIPHERSTASH_DATE_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: {
        kind: 'arg',
        index: 0,
        path: ['equality'],
        default: true,
      },
      orderAndRange: {
        kind: 'arg',
        index: 0,
        path: ['orderAndRange'],
        default: true,
      },
    },
  },
} as const satisfies AuthoringTypeConstructorDescriptor

const encryptedBooleanV2 = {
  kind: 'typeConstructor',
  args: [
    {
      kind: 'object',
      name: 'options',
      optional: true,
      properties: {
        equality: { kind: 'boolean', optional: true },
      },
    },
  ],
  output: {
    codecId: CIPHERSTASH_BOOLEAN_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: {
        kind: 'arg',
        index: 0,
        path: ['equality'],
        default: true,
      },
    },
  },
} as const satisfies AuthoringTypeConstructorDescriptor

const encryptedJsonV2 = {
  kind: 'typeConstructor',
  args: [
    {
      kind: 'object',
      name: 'options',
      optional: true,
      properties: {
        searchableJson: { kind: 'boolean', optional: true },
      },
    },
  ],
  output: {
    codecId: CIPHERSTASH_JSON_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      searchableJson: {
        kind: 'arg',
        index: 0,
        path: ['searchableJson'],
        default: true,
      },
    },
  },
} as const satisfies AuthoringTypeConstructorDescriptor

const v3Constructors: Record<string, AuthoringTypeConstructorDescriptor> =
  Object.fromEntries(
    EXPOSED_DOMAIN_ENTRIES.map(
      ([codecId, meta]) =>
        [v3PascalName(meta.bareDomain), v3Constructor(codecId, meta)] as const,
    ),
  )

// Dynamic construction loses the literal object type the old
// `as const satisfies` gave this file; the explicit `AuthoringTypeNamespace`
// annotation keeps the shape checked, and the 1:1 test in
// `test/authoring.test.ts` enforces the derived constructor set at runtime.
export const cipherstashAuthoringTypes: AuthoringTypeNamespace = {
  cipherstash: {
    ...v3Constructors,
    // v2 legacy aliases
    EncryptedStringV2: encryptedStringV2,
    EncryptedDoubleV2: encryptedDoubleV2,
    EncryptedBigIntV2: encryptedBigIntV2,
    EncryptedDateV2: encryptedDateV2,
    EncryptedBooleanV2: encryptedBooleanV2,
    EncryptedJsonV2: encryptedJsonV2,
  },
}
