# Security Policy

CipherStash takes the security of our software, infrastructure, and customers extremely seriously.
This document describes the security posture and reporting process for this repository.

## Supported Versions

EQL is distributed as a versioned SQL install bundle (`cipherstash-encrypt.sql`) attached to [GitHub releases](https://github.com/cipherstash/encrypt-query-language/releases), as the `ghcr.io/cipherstash/postgres-eql` Docker image, and via [dbdev](https://database.dev/cipherstash/eql).

**Security fixes are released for the latest release line.** Security reports are welcome for any version, but fixes land in the latest release — if you are running an older version, plan to upgrade to receive them.

Note that EQL itself performs no encryption or decryption: cryptographic operations are performed by the encryption client ([CipherStash Stack](https://github.com/cipherstash/stack), [CipherStash Proxy](https://github.com/cipherstash/proxy)). Vulnerabilities in those components are also in scope for the reporting process below — we will route them to the right team.

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

## Scope

The following are **in scope**:

- The `cipherstash/encrypt-query-language` GitHub repository
- Released SQL install bundles and the `postgres-eql` Docker image recipe
- EQL's encrypted index-term handling, operators, and type machinery
- Documentation or code examples that could lead to insecure usage
- CipherStash's internal infrastructure
- CipherStash Stack, Proxy, ZeroKMS, or other CipherStash products

The following are **out of scope**:

- Social engineering, physical attacks, or denial-of-service
- Attacks requiring privileged access to developer machines or CI/CD infrastructure

## Questions?

For general questions about CipherStash security practices (not security incidents), contact:

📧 **support@cipherstash.com**

For vulnerability disclosures:

📧 **security@cipherstash.com**

---

Thank you for helping keep the CipherStash ecosystem secure.
