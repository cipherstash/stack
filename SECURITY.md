# Security Policy

CipherStash takes the security of our software, infrastructure, and customers extremely seriously.
This document describes the security posture, reporting process, and guidelines for this repository and associated packages.

## Supported Packages

This repository contains the JavaScript/TypeScript SDK for CipherStash and related packages.

The below tables list each package along with the currently supported (receiving security updates).

### `@cipherstash/stack`

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4  | :x: |

### `@cipherstash/protect`

| Version | Supported          |
| ------- | ------------------ |
| 10.1.x   | :white_check_mark: |
| 9.6.x   | :white_check_mark:  |
| < 9.6   | :x: |

### `@cipherstash/drizzle`

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1  | :x: |

### `@cipherstash/schema`

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0  | :x: |

### `@cipherstash/protect-dynamodb`

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| < 5.1  | :x: |

### `@cipherstash/nextjs`

| Version | Supported          |
| ------- | ------------------ |
| 4.0.x   | :white_check_mark: |
| < 4.0  | :x: |

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

- The `cipherstash/protectjs` GitHub repository
- All published NPM packages under the `@cipherstash/protect*` namespace
- Protect.js cryptographic implementations, configuration layers, and CLI tooling
- Key-handling, authenticated encryption behaviour, JSON/JSONB field-level encryption flows
- Documentation or code examples that could lead to insecure usage
- CipherStash’s internal infrastructure
- CipherStash Proxy, ZeroKMS, or other backend products

The following are **out of scope**:

- Example applications in the `examples` dir (though we are still grateful for any relevant disclosires there)
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

The `release.yml` workflow publishes packages to npm using OIDC trusted
publishing and an `NPM_TOKEN`.

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
