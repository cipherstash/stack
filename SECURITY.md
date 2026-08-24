# Security Policy

CipherStash takes the security of our software, infrastructure, and customers extremely seriously.
This document describes the security posture, reporting process, and guidelines for this repository and associated packages.

## Supported Packages

This repository is the CipherStash Stack monorepo for JavaScript/TypeScript. It publishes the following packages to npm:

| Package | Description |
| ------- | ----------- |
| `@cipherstash/stack` | Main package: encryption client, schema, EQL v3 typed client |
| `stash` | CipherStash CLI |
| `@cipherstash/nextjs` | Next.js helpers |
| `@cipherstash/migrate` | Plaintext-to-encrypted column migration tooling |
| `@cipherstash/stack-prisma` | Prisma Next integration (searchable field-level encryption for Postgres) |
| `@cipherstash/stack-drizzle` | Drizzle ORM integration for `@cipherstash/stack` (EQL v3) |
| `@cipherstash/stack-supabase` | Supabase integration for `@cipherstash/stack` (EQL v3) |
| `@cipherstash/wizard` | AI-powered encryption setup |
| `@cipherstash/protect-ffi` | Native FFI bindings to the CipherStash Client SDK — the Rust core `@cipherstash/stack` encrypts and decrypts through |
| `@cipherstash/protect-ffi-darwin-arm64`<br>`@cipherstash/protect-ffi-darwin-x64`<br>`@cipherstash/protect-ffi-linux-arm64-gnu`<br>`@cipherstash/protect-ffi-linux-x64-gnu`<br>`@cipherstash/protect-ffi-linux-x64-musl`<br>`@cipherstash/protect-ffi-win32-x64-msvc` | Prebuilt per-platform binaries for `@cipherstash/protect-ffi`. Installed as optional dependencies; one is selected at load time for the host platform |
| `@cipherstash/eql` | Encrypt Query Language — the PostgreSQL SQL bundle (`eql_v3` schema: domains, operators, index-term extractors) that stores and queries encrypted payloads, plus its generated TypeScript types. Applied by `stash eql install` and by the Prisma Next adapter's migrations. Released in lockstep with the `eql-bindings` Rust crate, which emits the payloads this SQL reads |

This repository also carries the source of the **`eql-bindings`** Rust crate
(`packages/eql/crates/eql-bindings`), published to crates.io and released in
lockstep with `@cipherstash/eql`. It is in scope for security reports on the
same terms as the npm packages above.

> **Note on publishing.** `@cipherstash/eql` and the `eql-bindings` crate are
> developed here but are still *published* from
> `cipherstash/encrypt-query-language` — the npm package's `repository` /
> `bugs` fields and the crate's `repository` / `homepage` all still name it, as
> does npm trusted publishing, and repointing every one of them is Phase 5 of
> `docs/plans/2026-08-13-eql-monorepo-absorption.md`. Everything else in the
> table above — including all seven `@cipherstash/protect-ffi*` packages, whose
> own cutover has completed — is published from this repository by
> `.github/workflows/release.yml`. Source, issues, and security reports for all
> of them belong here regardless.
>
> The provenance attestation on a release names the repository that built it,
> and is the only thing that settles the paragraph above:
> `curl -s https://registry.npmjs.org/-/npm/v1/attestations/@cipherstash%2fprotect-ffi@0.32.0`
> returns `cipherstash/stack`; the same call against `@cipherstash%2feql@3.0.5`
> returns `cipherstash/encrypt-query-language`. Check there before repeating
> either claim: this note went on naming `cipherstash/protectjs-ffi` as the
> protect-ffi publisher through `0.32.0` — the release that proved the cutover
> and disproved the sentence.
>
> `scripts/__tests__/frozen-publisher-docs.test.mjs` now holds this paragraph to
> `FROZEN_PUBLISHERS` in `scripts/release-gate.mjs`. It fails if the note names
> a package the map does not freeze, and fails again on the Phase-5 cutover that
> empties the map — so the next half of this note to go stale does so loudly.

**Security fixes are released for the latest release line of each package.** Security reports are welcome for any version, but fixes land in the latest release — if you are running an older major version, plan to upgrade to receive them.

All packages follow semantic versioning and undergo internal security review, automated analysis, and reproducible builds as part of our SDLC.

---

## Reporting a Vulnerability

If you believe you have found a security vulnerability in any CipherStash code, service, or dependency:

📧 **Please email: `security@cipherstash.com`**

We request that you **do not publicly disclose** the issue before we have had a chance to investigate and provide a fix.

When reporting, please include (as applicable):

- Description of the vulnerability
- Steps to reproduce
- Impact assessment or potential misuse
- Any relevant logs, PoCs, or screenshots
- Suggested remediation (if you have one)

We will acknowledge receipt within **48 hours** and provide regular updates until the issue is resolved.

---

## Disclosure & Response Policy

CipherStash follows a **coordinated responsible disclosure** process:

1. **Submit report** privately via `security@cipherstash.com`.
2. **Acknowledgement** within 48 hours.
3. **Assessment** of severity using CVSS and internal risk models.
4. **Fix development** and patch release in a private branch.
5. **Coordinated disclosure**, including:
   - New patch release(s)
   - Security advisory on GitHub
   - Credit to reporter (optional)

We will never take legal action against good-faith security researchers who follow this policy.

---

## Scope

The following are **in scope**:

- The `cipherstash/stack` GitHub repository
- All npm packages listed under Supported Packages above — scope follows the source, not the release pipeline (see the note on publishing)
- CipherStash Stack cryptographic implementations, configuration layers, and CLI tooling
- Key-handling, authenticated encryption behaviour, JSON/JSONB field-level encryption flows
- Documentation or code examples that could lead to insecure usage
- CipherStash’s internal infrastructure
- CipherStash Proxy, ZeroKMS, or other backend products

The following are **out of scope**:

- Example applications in the `examples` dir (though we are still grateful for any relevant disclosures there)
- Social engineering, physical attacks, or denial-of-service
- Attacks requiring privileged access to developer machines or CI/CD infrastructure

---

## Security Guidelines for Contributors

To maintain a strong security posture, contributors MUST:

### ⚙️ Follow cryptographic safety rules
- Do **not** modify cryptographic primitives without prior discussion
- Avoid introducing new crypto dependencies without prior discussion
- Never check in test keys, secrets, or example credentials

### 🛡 Coding & dependency hygiene
- Avoid adding dependencies unless necessary
- Keep dependencies updated and vetted
- Use TypeScript for all new code
- Ensure all code paths that handle keys or encrypted data include type-safe boundaries

### 🔍 Testing & review
- Submit PRs with tests covering edge cases and misuse-resistant behaviour
- Flag any changes involving key derivation, key wrapping, AAD, or encryption modes for mandatory security review
- Do not merge PRs that downgrade security controls or introduce unsafe defaults

---

## CI/CD Supply-Chain Hardening

This repo applies a set of supply-chain controls sourced from
[lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices):
a post-install script policy, a 7-day dependency cooldown (pnpm
`minimumReleaseAge`, mirrored by Dependabot's cooldown), exotic-dependency
blocking (`blockExoticSubdeps`), frozen-lockfile CI, registry pinning, and
CODEOWNERS coverage of supply-chain-critical paths. These controls are
validated by `e2e/tests/supply-chain.e2e.test.ts` so silent regressions fail
CI. See `skills/stash-supply-chain-security/SKILL.md` for the full guide.

The `release.yml` workflow publishes packages to npm using OIDC trusted
publishing (`id-token: write`). There is no long-lived `NPM_TOKEN` — the
workflow deliberately avoids one, and setting one would bypass trusted
publishing. `release-plz.yml` publishes the `eql-bindings` crate to crates.io
over the same token exchange, and likewise carries no `CARGO_REGISTRY_TOKEN`.
Both bind to a *workflow filename* at the registry, so renaming either file
silently invalidates its publisher configuration.

`scripts/__tests__/workflow-publish-permissions.test.mjs` holds the shape those
two files must keep: `id-token: write` is granted per job and never at workflow
level (where it would be a default inherited by every job in a file the registry
already trusts), and a job in such a file that does not publish may not hold a
writable scope. Both lists are equalities, so a new publisher — or a new job
that can write to the repository the publishers build from — has to be argued
for in the same diff.

[GitHub Actions cache poisoning is a known attack][1] against credential-bearing
workflows. The mechanism is:

- A lower-privileged workflow run plants a malicious entry under a deterministic
  cache key
- A privileged workflow restores a cache from that deterministic cache key
- The malicious entry is executed by the privileged workflow, and secrets
  are exfiltrated

We mitigate this by:

- Explicitly disabling all caching in every workflow that publishes an artefact
  — `release.yml`, the reusables it calls (`_build-ffi-artifacts.yml`,
  `_build-eql-sql.yml`, `_build-eql-docs.yml`), `release-plz.yml` and
  `release-postgres-eql-image.yml`
- Automated checks for disabled caching on high-risk workflows
  (`scripts/lint-no-workflow-caching.mjs`). It works from an ALLOWLIST of
  audited actions rather than a denylist of cache actions, so an action it has
  never seen is a finding by default — the cases that matter most are
  `setup-<tool>` actions that cache by default, with no `cache:` input and no
  telling name. The cost is real and accepted: four EQL release jobs compile
  Rust with no `Swatinem/rust-cache` restore.

[1]: https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/

---

## Questions?

For general questions about CipherStash security practices (not security incidents), contact:

📧 **support@cipherstash.com**

For vulnerability disclosures:

📧 **security@cipherstash.com**

---

Thank you for helping keep the CipherStash ecosystem secure.
