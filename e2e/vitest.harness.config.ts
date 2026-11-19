import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Real Runs provision disposable stores; fail promptly rather than spend
    // minutes on later variants when the reference or infrastructure is broken.
    bail: 1,
    include: ['migration-harness/__tests__/**/*.test.ts'],
    exclude: ['**/node_modules/**'],
  },
})
