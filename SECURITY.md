# Security Policy

CipherStash takes the security of our software, infrastructure, and customers extremely seriously.
This document describes the security posture, reporting process, and guidelines for this repository and associated packages.

## Supported Packages

This repository is the CipherStash Stack monorepo for JavaScript/TypeScript. It publishes the following packages to npm:

| Package | Description |
| ------- | ----------- |
| `@cipherstash/stack` | Main package: encryption client and all integrations |
| `stash` | CipherStash CLI |
| `@cipherstash/protect` | Core encryption library (re-exported via `@cipherstash/stack`) |
| `@cipherstash/schema` | Schema builder utilities |
| `@cipherstash/drizzle` | Drizzle ORM integration |
| `@cipherstash/nextjs` | Next.js helpers |
| `@cipherstash/protect-dynamodb` | DynamoDB helpers |
| `@cipherstash/migrate` | Plaintext-to-encrypted column migration tooling |
| `@cipherstash/prisma-next` | Prisma Next integration (searchable field-level encryption for Postgres) |
| `@cipherstash/wizard` | AI-powered encryption setup |

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
- All npm packages published from this repository (listed under Supported Packages above)
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
publishing.

[GitHub Actions cache poisoning is a known attack][1] against credential-bearing
workflows. The mechanism is:

- A lower-privileged workflow run plants a malicious entry under a deterministic
  cache key
- A privileged workflow restores a cache from that deterministic cache key
- The malicious entry is executed by the privileged workflow, and secrets
  are exfiltrated

We mitigate this by:

- Explicitly disabling all caching in `release.yml`
- Automated checks for disabled caching on high-risk workflows

[1]: https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/

---

## Questions?

For general questions about CipherStash security practices (not security incidents), contact:

📧 **support@cipherstash.com**

For vulnerability disclosures:

📧 **security@cipherstash.com**

---

Thank you for helping keep the CipherStash ecosystem secure.
