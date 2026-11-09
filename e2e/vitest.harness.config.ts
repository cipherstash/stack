import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['migration-harness/__tests__/**/*.test.ts'],
    exclude: ['**/node_modules/**'],
  },
})
