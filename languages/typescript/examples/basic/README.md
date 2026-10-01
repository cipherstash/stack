# Basic example of using @cipherstash/stack

This basic example demonstrates how to use the `@cipherstash/stack` package and the **Encryption SDK** to encrypt and decrypt arbitrary input.

## Installing the basic example

> [!IMPORTANT]
> You need Node.js 22+ and npm (or [pnpm](https://pnpm.io/installation)).

Create a new project or use an existing one, then install the package:

```bash
npm install @cipherstash/stack dotenv
```

Or with pnpm:

```bash
pnpm add @cipherstash/stack dotenv
```

> [!NOTE]
> `dotenv` is only needed if you are loading credentials from a `.env` file. It is not a dependency of `@cipherstash/stack`.

You can also clone this repo and run the example as-is from `examples/basic` (after `pnpm install` in the repo root and in `examples/basic`).

## Configuring the basic example

Create a [CipherStash account](https://cipherstash.com) and get your workspace credentials from the [CipherStash dashboard](https://app.cipherstash.com). You will need:

- **Workspace CRN** (Cloud Resource Name)
- **Client ID**
- **Client key**
- **Client access key**

Set these as environment variables (e.g. in a `.env` file in your project root):

```bash
CS_WORKSPACE_CRN=crn:...
CS_CLIENT_ID=...
CS_CLIENT_KEY=...
CS_CLIENT_ACCESS_KEY=...
```

> [!WARNING]
> Do not commit `.env` or any file containing these credentials to git.

## Using the basic example

Run your script (e.g. `node --import tsx index.ts` or `pnpm start` if you use the example’s script). The application will prompt for a name, encrypt it with CipherStash, log the ciphertext, decrypt it, and log the original plaintext, then run a short bulk-encryption demo.
