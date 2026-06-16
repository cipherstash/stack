/**
 * Public middleware surface for the cipherstash extension.
 *
 * Consumers register the bulk-encrypt middleware in their runtime so
 * `EncryptedString` envelopes embedded in `INSERT` / `UPDATE` plans get
 * encrypted in batches before encode runs:
 *
 * ```ts
 * import { createCipherstashRuntimeDescriptor } from '@prisma-next/extension-cipherstash/runtime';
 * import { bulkEncryptMiddleware } from '@prisma-next/extension-cipherstash/middleware';
 *
 * const runtime = createRuntime({
 *   extensionPacks: [createCipherstashRuntimeDescriptor({ sdk })],
 *   middleware: [bulkEncryptMiddleware(sdk)],
 * });
 * ```
 *
 * `SqlRuntimeExtensionDescriptor` does not own a middleware slot, so
 * the descriptor wrapper (`createCipherstashRuntimeDescriptor`) and
 * the middleware are composed manually by callers — by convention,
 * once per cipherstash SDK binding.
 */

export { bulkEncryptMiddleware } from '../middleware/bulk-encrypt';
// EQL v3 storage-vs-search-term split middleware. Register ALONGSIDE
// bulkEncryptMiddleware (disjoint codec-id sets — each ignores the other's params).
export { bulkEncryptV3Middleware } from '../middleware/bulk-encrypt-v3';
