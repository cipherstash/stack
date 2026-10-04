import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    watch: false,
    testTimeout: 30000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'lcov'],
      reportsDirectory: './coverage',
      include: ['../src/**/*.ts', '../src/**/*.cts', '../src/**/*.mts'],
      exclude: ['**/node_modules/**', '**/tests/**'],
    },
  },
})
