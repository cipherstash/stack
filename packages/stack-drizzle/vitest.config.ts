import { configDefaults, defineConfig } from 'vitest/config'
import { sharedAlias, stackSourceAlias } from '../../vitest.shared'

export default defineConfig({
  resolve: {
    // See stack-supabase/vitest.config.ts for what these two alias blocks do.
    alias: { ...sharedAlias, ...stackSourceAlias },
  },
  test: {
    exclude: [...configDefaults.exclude, 'integration/**'],
    testTimeout: 30000,
    hookTimeout: 30000,
    typecheck: {
      tsconfig: './tsconfig.typecheck.json',
      include: ['__tests__/**/*.test-d.ts'],
    },
  },
})
