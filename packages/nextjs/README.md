# @cipherstash/nextjs

Next.js helpers for CipherStash encryption, including Clerk integration via the `@cipherstash/nextjs/clerk` export.

This package is part of the [CipherStash Stack](https://github.com/cipherstash/stack). For most applications we recommend the main [`@cipherstash/stack`](https://www.npmjs.com/package/@cipherstash/stack) package.

- [Documentation](https://cipherstash.com/docs)
- [Identity-aware encryption](https://cipherstash.com/docs/stack/cipherstash/encryption/identity)

> [!IMPORTANT]
> The default `@cipherstash/stack` entry relies on a native Node.js module and must be excluded from bundling — see the [bundling guide](https://cipherstash.com/docs/stack/deploy/bundling) for the required `serverExternalPackages` configuration in Next.js.
> Alternatively, `@cipherstash/stack/wasm-inline` is designed to be bundled (no native module) and works in edge/serverless runtimes.
