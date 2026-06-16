// Regenerates src/migration/eql-v3-install.generated.ts from the vendored
// __tests__/fixtures/cipherstash-encrypt-v3.sql installer.
//
// Run: pnpm tsx scripts/vendor-eql-v3-install.ts
//
// See scripts/REFRESH_EQL_V3.md for the full refresh procedure (which EQL commit
// the fixture is built from, the cross-package duplication hazard, etc.).
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(import.meta.dirname, '..')
const SRC = join(ROOT, '__tests__/fixtures/cipherstash-encrypt-v3.sql')
const OUT = join(ROOT, 'src/migration/eql-v3-install.generated.ts')
const VERSION = 'eql-v3-035952e' // EQL repo commit the fixture was built from

const sql = readFileSync(SRC, 'utf8')
// Escape order matters: backslash FIRST (so the backslashes we insert below
// are not themselves re-escaped), then backtick, then ${ template openers.
const escaped = sql.replaceAll('\\', '\\\\').replaceAll('`', '\\`').replaceAll('${', '\\${')

writeFileSync(
  OUT,
  `// @generated — DO NOT EDIT.\n` +
    `// Source: scripts/vendor-eql-v3-install.ts\n` +
    `// Origin fixture: __tests__/fixtures/cipherstash-encrypt-v3.sql\n` +
    `//\n` +
    `// This file is committed to source control so dev environments and offline\n` +
    `// builds work without network access. Regenerate with\n` +
    `// \`pnpm tsx scripts/vendor-eql-v3-install.ts\` after refreshing the fixture.\n` +
    `export const EQL_V3_INSTALL_VERSION = '${VERSION}' as const\n` +
    `export const EQL_V3_INSTALL_SQL: string = \`${escaped}\`\n`,
)
console.log(`Wrote ${OUT} (${sql.length} bytes of SQL)`)
