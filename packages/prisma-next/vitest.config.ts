import { configDefaults, defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // Integration suites run only under `test:integration` (own config +
    // CI job) — same split as stack-drizzle / stack-supabase.
    exclude: [...configDefaults.exclude, 'integration/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'dist/**',
        'test/**',
        '**/*.test.ts',
        '**/*.test-d.ts',
        '**/*.config.ts',
        '**/exports/**',
        // Emitted contract artefact (typecheck-only).
        'src/contract.d.ts',
      ],
    },
  },
})
