import { describe, expect, it } from 'vitest'
import scriptsVitestConfig from '../vitest.config.mjs'

describe('scripts vitest config', () => {
  it('keeps script test files serialized', () => {
    expect(scriptsVitestConfig.test.fileParallelism).toBe(false)
  })
})
