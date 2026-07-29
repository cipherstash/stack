<div align="center">
  <a href="https://cipherstash.com">
    <img alt="CipherStash Logo" loading="lazy" width="128" height="128" decoding="async" data-nimg="1" style="color:transparent" src="https://cipherstash.com/brand/cipherstash-logo-dark.svg">
  </a>
  <h1>CipherStash Stack for TypeScript</h1>

<a href="https://cipherstash.com"><img alt="Built by CipherStash" src="https://raw.githubusercontent.com/cipherstash/meta/refs/heads/main/csbadge.svg?style=for-the-badge&labelColor=000"></a>
<a href="https://github.com/cipherstash/stack/blob/main/LICENSE.md"><img alt="License" src="https://img.shields.io/npm/l/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000"></a>
<a href="https://cipherstash.com/docs"><img alt="Docs" src="https://img.shields.io/badge/Docs-333333.svg?style=for-the-badge&logo=readthedocs&labelColor=333"></a>
<a href="https://discord.gg/5qwXUFb6PB"><img alt="Join the community on Discord" src="https://img.shields.io/badge/Join%20the%20community-blueviolet.svg?style=for-the-badge&logo=Discord&labelColor=000000&logoWidth=20"></a>

</div>

## What is the stack?

- [Encryption](https://cipherstash.com/docs/stack/cipherstash/encryption): Field-level encryption for TypeScript apps with searchable encrypted queries, zero-knowledge key management, and first-class ORM support.

## Quick look at the stack in action

**Encryption**

```typescript
import { Encryption, encryptedTable, types } from "@cipherstash/stack/v3";

// 1. Define your schema — the column type fixes its query capabilities
const users = encryptedTable("users", {
  email: types.TextSearch("email"), // equality + order/range + free-text search
});

// 2. Initialize the client
const client = await Encryption({ schemas: [users] });

// 3. Encrypt
const encryptResult = await client.encrypt("secret@example.com", {
  column: users.email,
  table: users,
});
if (encryptResult.failure) {
  // Handle errors your way
}

// 4. Decrypt
const decryptResult = await client.decrypt(encryptResult.data);
if (decryptResult.failure) {
  // Handle errors your way
}
// decryptResult.data => "secret@example.com"
```

## Install

```bash
npm install @cipherstash/stack
# or
yarn add @cipherstash/stack
# or
pnpm add @cipherstash/stack
# or
bun add @cipherstash/stack
```

> [!IMPORTANT]
> **You need to opt out of bundling when using `@cipherstash/stack`.**
> It uses Node.js specific features and requires the native Node.js `require`.
> Read more about bundling in the [documentation](https://cipherstash.com/docs/stack/deploy/bundling).

## Features

- **[Searchable encryption](https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption)**: query encrypted data with equality, free text search, range, and [JSONB queries](https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption#jsonb-queries-with-searchablejson).
- **[Type-safe schema](https://cipherstash.com/docs/stack/cipherstash/encryption/schema)**: define encrypted tables and columns with `encryptedTable` and the `types.*` concrete-domain factories
- **[Model & bulk operations](https://cipherstash.com/docs/stack/cipherstash/encryption/encrypt-decrypt#model-operations)**: encrypt and decrypt entire objects or batches with `encryptModel` / `bulkEncryptModels`.
- **[Identity-aware encryption](https://cipherstash.com/docs/stack/cipherstash/encryption/identity)**: authenticate as the end user with `OidcFederationStrategy` and bind the data key to their identity with `.withLockContext({ identityClaim })` for policy-based access control.

## Integrations

- [Encryption + Drizzle](https://cipherstash.com/docs/stack/cipherstash/encryption/drizzle)
- [Encryption + Supabase](https://cipherstash.com/docs/stack/cipherstash/encryption/supabase)
- [Encryption + DynamoDB](https://cipherstash.com/docs/stack/cipherstash/encryption/dynamodb)

## Use cases

- **Trusted data access**: ensure only your end-users can access their sensitive data using identity-bound encryption
- **Reduce breach impact**: limit the blast radius of exploited vulnerabilities to only the data the affected user can decrypt

## Documentation

- [Documentation](https://cipherstash.com/docs)
- [Quickstart](https://cipherstash.com/docs/stack/quickstart)
- [SDK and API reference](https://cipherstash.com/docs/stack/reference)

## Contributing

Contributions are welcome and highly appreciated. However, before you jump right into it, we would like you to review our [Contribution Guidelines](CONTRIBUTE.md) to make sure you have a smooth experience contributing.

## Security

For our full security policy, supported versions, and contributor guidelines, see [SECURITY.md](./SECURITY.md).

## License

This project is [MIT licensed](./LICENSE.md).
