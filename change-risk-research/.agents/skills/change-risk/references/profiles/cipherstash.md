# Repository profile: CipherStash (`cipherstash/*`)

Use with any CipherStash repository. Read the repository's own `AGENTS.md`, `CLAUDE.md`, `README.md` and `SECURITY.md` **at the revision being assessed** (`git show $HEAD:AGENTS.md`); they describe the package layout and contracts as they were at that point. Do not assume today's layout applies to an older revision.

These are investigation prompts. Raise impact for a mechanism, not for a match.

## What CipherStash software does
Application-level, per-value encryption. Client libraries encrypt values before they reach a database or service, using keys managed by ZeroKMS. Encrypted values are stored as structured payloads (EQL) that SQL functions in PostgreSQL can index and query without decrypting. A defect is most severe when it lets plaintext out, encrypts under the wrong key or identity, or writes a payload readers cannot handle.

## Contracts that consumers depend on
- **The encrypted payload shape.** Keys and structure of stored payloads are read by SQL functions, other language clients and customers' stored data. A change in what is written, or in what is accepted on read, is a cross-version compatibility question with data already at rest.
- **Client library and SQL bundle pairing.** Search terms produced by a client must match what the installed SQL functions expect. Ask what happens when only one side is upgraded.
- **Operation results.** Encryption operations return a result object (`data` or `failure`, with stable error `type` strings). Callers branch on these.
- **Lock context / identity binding.** When an operation is bound to an end-user identity, the same binding must apply on encrypt and decrypt, and on every path (single, bulk, model, query).
- **Module formats and entry points.** Packages ship ESM and CJS, a native-module entry and (where present) a WASM entry. Each entry a consumer can import is part of the contract, including its type declarations.
- **The native binding.** A Node-API native module per platform. Every per-platform binary is part of what ships.

## What ships to customers that is not library code
- CLI commands, flags, prompts and generated files (configs, migrations, scaffolded code).
- Agent skills and instructions bundled into packages and copied into customer repositories. They are not type-checked, so drift becomes wrong guidance in someone else's codebase.
- SQL install bundles applied to customer databases.

## Release mechanics
- Several packages may version together, and some artefacts (npm package, crate, SQL bundle, docs, image) must ship at one version. Look for anything that can move one without the others.
- Publishing is effectively irreversible; a broken release needs a new release.
- Release workflows run with publishing credentials. Treat changes to them as security-sensitive.

## Signals that usually do not raise impact here
- Documentation-only changes outside shipped skills and READMEs.
- Dev-dependency bumps that do not affect build output.
- Test-only changes (but check whether a test that guarded something was removed or weakened).
