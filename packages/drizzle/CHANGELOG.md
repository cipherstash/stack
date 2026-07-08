# @cipherstash/drizzle

## 3.0.3

### Patch Changes

- aa9c4b1: Documentation: refresh package READMEs after the protectjs → stack repository rename. Fixed repository and license links, replaced dead in-repo docs links with cipherstash.com/docs URLs, rewrote the incorrect @cipherstash/nextjs README, and added guidance pointing new projects to @cipherstash/stack.

## 3.0.2

### Patch Changes

- a8dbb65: Render every user-facing CLI string and execute every shell-out under the detected package manager (`npx` / `bunx` / `pnpm dlx` / `yarn dlx`), completing the work started in #379. Affected surfaces: `@cipherstash/cli` top-level + `auth` + `env` help, `db install` Drizzle migration steps, `db migrate` not-implemented warning, the Supabase migration SQL header, the Supabase status fallback exec, the `@cipherstash/protect` `stash` Stricli help (set/get/list/delete), the `@cipherstash/wizard` usage line and agent command allowlist, and the `@cipherstash/drizzle` `generate-eql-migration` help + drizzle-kit invocation. A new `pnpm run lint:runners` lint runs in CI and fails on any reintroduction of a hardcoded runner literal.

## 3.0.1

### Patch Changes

- b0e56b8: Upgrade protect-ffi to 0.21.0 and enable array_index_mode for searchable JSON

  - Upgrade `@cipherstash/protect-ffi` to 0.21.0 across all packages
  - Enable `array_index_mode: 'all'` on STE vec indexes so JSON array operations
    (jsonb_array_elements, jsonb_array_length, array containment) work correctly
  - Delegate credential resolution entirely to protect-ffi's `withEnvCredentials`
  - Download latest EQL at build/runtime instead of bundling hardcoded SQL files

## 3.0.0

### Patch Changes

- db72e2c: Add `encryptQuery` API for encrypting query terms with explicit query type selection.

  - New `encryptQuery()` method replaces `createSearchTerms()` with improved query type handling
  - Supports `equality`, `freeTextSearch`, and `orderAndRange` query types
  - Deprecates `createSearchTerms()` - use `encryptQuery()` instead
  - Updates drizzle operators to use correct index selection via `queryType` parameter

- Updated dependencies [db72e2c]
- Updated dependencies [e769740]
  - @cipherstash/protect@10.5.0
  - @cipherstash/schema@2.1.0

## 2.3.0

### Patch Changes

- Updated dependencies [9ccaf68]
  - @cipherstash/protect@10.4.0

## 2.2.0

### Patch Changes

- Updated dependencies [a1fce2b]
- Updated dependencies [622b684]
  - @cipherstash/protect@10.3.0

## 2.1.0

### Minor Changes

- 41c4169: Update drizzle imports to use /client export path from Protect.js.

## 2.0.0

### Patch Changes

- Updated dependencies [de029de]
  - @cipherstash/protect@10.2.0

## 1.1.1

### Patch Changes

- ff4421f: Expanded typedoc documentation
- Updated dependencies [ff4421f]
  - @cipherstash/protect@10.1.1
  - @cipherstash/schema@2.0.1

## 1.1.0

### Patch Changes

- Updated dependencies [6b87c17]
  - @cipherstash/protect@10.1.0

## 1.0.0

### Minor Changes

- 2edfedd: Added support for encrypted or operation.
- 7b8c719: Added `generate-eql-migration` CLI command to automate EQL migration generation.

  This command consolidates the manual process of running `drizzle-kit generate --custom` and populating the SQL file into a single command. It uses the bundled EQL SQL from `@cipherstash/schema` for offline-friendly, version-locked installations.

  Usage:

  ```bash
  npx generate-eql-migration
  npx generate-eql-migration --name setup-eql
  npx generate-eql-migration --out migrations
  ```

### Patch Changes

- Updated dependencies [9005484]
  - @cipherstash/schema@2.0.0
  - @cipherstash/protect@10.0.2

## 0.2.0

### Minor Changes

- ebda487: Added explicit return type to extractProtectSchem.

## 0.1.0

### Minor Changes

- d8ed4d4: Released initial Drizzle ORM interface.

### Patch Changes

- Updated dependencies [d8ed4d4]
  - @cipherstash/schema@1.1.0
  - @cipherstash/protect@10.0.1
