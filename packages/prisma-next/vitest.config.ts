import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    // Run the type-level `*.test-d.ts` suites as part of `pnpm test` (vitest
    // run). Without this they only fail via `pnpm typecheck`; enabling typecheck
    // here surfaces a broken type-augmentation in the normal test run too.
    typecheck: {
      enabled: true,
      include: ['**/*.test-d.ts'],
      tsconfig: './tsconfig.json',
    },
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
});
