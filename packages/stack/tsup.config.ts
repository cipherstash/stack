import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: [
      'src/index.ts',
      'src/client.ts',
      'src/types-public.ts',
      'src/identity/index.ts',
      'src/secrets/index.ts',
      'src/schema/index.ts',
      'src/drizzle/index.ts',
      'src/dynamodb/index.ts',
      'src/supabase/index.ts',
      'src/encryption/index.ts',
      'src/errors/index.ts',
    ],
    format: ['cjs', 'esm'],
    sourcemap: true,
    dts: true,
    clean: true,
    target: 'es2022',
    tsconfig: './tsconfig.json',
    external: ['drizzle-orm', '@supabase/supabase-js'],
    noExternal: ['evlog', 'uuid'],
  },
])
