import { describe, expect, it } from 'vitest'
import {
  CIPHERSTASH_EXTENSION_VERSION,
  CIPHERSTASH_SPACE_ID,
} from '../../src/extension-metadata/constants'
import {
  CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME,
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_CODEC_ID_SET,
  CIPHERSTASH_V3_CODEC_IDS,
  CIPHERSTASH_V3_EXTENSION_VERSION,
  CIPHERSTASH_V3_INVARIANTS,
  CIPHERSTASH_V3_SPACE_ID,
  isCipherstashV3CodecId,
  v3TraitsForCapabilities,
} from '../../src/extension-metadata/constants-v3'
import { V3_CODEC_IDS } from '../../src/v3/catalog'

describe('constants-v3', () => {
  it('the PINNED codec-id tuple equals the registry-derived set (drift guard, runtime side)', () => {
    // The compile-time `satisfies` + `Exclude` guards catch type drift; this
    // catches derivation drift (e.g. the registry iteration silently dropping
    // or reordering a domain). Both directions must hold.
    expect(new Set(CIPHERSTASH_V3_CODEC_IDS)).toEqual(new Set(V3_CODEC_IDS))
    expect(CIPHERSTASH_V3_CODEC_IDS.length).toBe(V3_CODEC_IDS.length)
    expect(new Set(CIPHERSTASH_V3_CODEC_IDS).size).toBe(
      CIPHERSTASH_V3_CODEC_IDS.length,
    )
  })

  it('guard narrows only v3 ids', () => {
    expect(isCipherstashV3CodecId('cipherstash/eql-v3/eql_v3_text_eq@1')).toBe(
      true,
    )
    expect(isCipherstashV3CodecId('cipherstash/string@1')).toBe(false)
    // GA registry keys are eql_v3_*-prefixed; the un-prefixed form is NOT an id.
    expect(isCipherstashV3CodecId('cipherstash/eql-v3/text_eq@1')).toBe(false)
    expect(
      CIPHERSTASH_V3_CODEC_ID_SET.has('cipherstash/eql-v3/eql_v3_text_eq@1'),
    ).toBe(true)
  })

  it('derives cipherstash-namespaced traits from capabilities', () => {
    expect(
      [
        ...v3TraitsForCapabilities({
          equality: true,
          orderAndRange: true,
          freeTextSearch: true,
        }),
      ].sort(),
    ).toEqual([
      'cipherstash:equality',
      'cipherstash:free-text-search',
      'cipherstash:order-and-range',
    ])
    expect(
      v3TraitsForCapabilities({
        equality: false,
        orderAndRange: false,
        freeTextSearch: false,
      }),
    ).toEqual([])
    expect(
      v3TraitsForCapabilities({
        equality: false,
        orderAndRange: false,
        freeTextSearch: false,
        searchableJson: true,
      }),
    ).toEqual(['cipherstash:searchable-json'])
  })

  it('pins the migration name + invariant', () => {
    expect(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME).toBe(
      '20260601T0100_install_eql_v3_bundle',
    )
    expect(CIPHERSTASH_V3_INVARIANTS.installBundle).toBe(
      'cipherstash:install-eql-v3-bundle-v1',
    )
    expect(CIPHERSTASH_V3_302_UPGRADE_MIGRATION_NAME).toBe(
      '20260720T0000_upgrade_eql_v3_3_0_2',
    )
    expect(CIPHERSTASH_V3_INVARIANTS.upgradeBundle302).toBe(
      'cipherstash:upgrade-eql-v3-bundle-3.0.2-v1',
    )
  })

  it('v3 extension identity is distinct from v2 (decision 1b — separate entry points)', () => {
    expect(CIPHERSTASH_V3_SPACE_ID).not.toBe(CIPHERSTASH_SPACE_ID)
    expect(CIPHERSTASH_V3_EXTENSION_VERSION).not.toBe(
      CIPHERSTASH_EXTENSION_VERSION,
    )
  })
})
