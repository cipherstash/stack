/**
 * The command registry is plain data with no imports, so `decrypt backfill`'s
 * help writes its flag names and limits as literals. These tests hold them to
 * the constants the command enforces, so the help cannot drift from them.
 */

import { MAX_DECRYPT_CHUNK_SIZE } from '@cipherstash/migrate'
import { describe, expect, it } from 'vitest'
import { renderCommandHelp } from '@/cli/help.js'
import { DEFAULT_DECRYPT_CHUNK_SIZE } from '../backfill.js'
import { TWIN_HAZARD_FLAGS } from '../lib/resolve-pair.js'

const help = renderCommandHelp('decrypt backfill', 'npx stash') ?? ''

describe('decrypt backfill help', () => {
  it('states the chunk-size bound and default the command enforces', () => {
    expect(help).toContain(`from 1 to ${MAX_DECRYPT_CHUNK_SIZE}`)
    expect(help).toMatch(
      new RegExp(`--chunk-size <n>[\\s\\S]*${DEFAULT_DECRYPT_CHUNK_SIZE}`),
    )
  })

  it.each(Object.values(TWIN_HAZARD_FLAGS))(
    'offers %s, a way past a twin that holds values, as a flag',
    (flag) => {
      expect(help).toContain(`  ${flag}`)
    },
  )
})
