/**
 * The v3 domain catalog moved to `@cipherstash/test-kit` so the integration
 * suites — which after the adapter split live in other packages — can import
 * the same single source of truth. A package must not reach into another
 * package's `__tests__` tree, and duplicating the catalog would let the two
 * copies disagree about which domains exist.
 *
 * This shim keeps the ~12 unit suites that import `../v3-matrix/catalog`
 * unchanged. Import from `@cipherstash/test-kit` in anything new.
 */
export * from '@cipherstash/test-kit/catalog'
