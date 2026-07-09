# @cipherstash/wizard

AI-powered encryption setup for CipherStash. Reads your codebase, asks which
columns to encrypt, and wires up `@cipherstash/stack` for you.

## Usage

Run it via your package manager's runner — the wizard installs nothing
permanently and is intended to be invoked once per project:

```bash
npx @cipherstash/wizard       # npm / Node
pnpm dlx @cipherstash/wizard  # pnpm
yarn dlx @cipherstash/wizard  # yarn
bunx @cipherstash/wizard      # bun
```

## Prerequisites

Before running the wizard, your project should have:

- `stash` available (the wizard shells out to `stash eql install` /
  `db push` after the agent finishes editing)
- A `stash.config.ts` (or the wizard will run `stash eql install` to scaffold one)
- A reachable database via `DATABASE_URL`
- An authenticated CipherStash session (`stash auth login`)

## What it does

1. Detects your framework (Drizzle, Supabase, Prisma, generic) and TypeScript usage.
2. Runs health checks against the CipherStash gateway and your database.
3. Prompts you to pick the tables and columns to encrypt.
4. Hands a surgical prompt to the Claude Agent SDK, which edits your schema
   and call sites to use `@cipherstash/stack`'s encryption APIs.
5. Runs deterministic post-agent steps: package install, `eql install`,
   `db push`, framework-specific migrations.
6. Reports remaining call sites that need `encryptModel` / `decryptModel`
   wiring.

The agent runs against a CipherStash-hosted LLM gateway — you authenticate
with your CipherStash account, no Anthropic API key required.

## License

MIT — see [LICENSE](./LICENSE).
