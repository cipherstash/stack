---
name: misuse-resistance
description: Misuse-resistant API design for cryptography and sensitive data. Use when designing or reviewing a public API that handles keys, secrets, ciphertext, nonces or randomness; when writing docs or examples for a security library; or when adding warnings or errors to one.
---

# Misuse resistance

Internal skill. It lives in `.claude/skills/` on purpose: `skills/` ships to customers inside the `stash` tarball, and this skill must not.

This skill is a copy. The source is `.claude/skills/misuse-resistance/` in [cipherstash/vitaminc](https://github.com/cipherstash/vitaminc), at commit `06861c1b9` on `main` (17 November 2026). `RUST.md` and `EVIDENCE.md` are unchanged. `SKILL.md` differs in this note and in its last section. To update the copy, copy the three files again, then restore this note and the last section. Propose a change to a rule in vitaminc, not here, so the two copies stay the same.

A **footgun** is an API whose obvious use is insecure. Most cryptographic failures are footguns fired at the call site: in one study, 83% of crypto CVEs were applications misusing correct libraries. That count covers only CVEs tagged as cryptographic, so library bugs filed under other tags, such as Heartbleed, are outside it. The people firing them, developers and coding agents alike, optimise for code that works, copy examples verbatim, and rate their insecure code as secure. Security therefore has to come from the API itself: the shortest path that works must be the secure path.

Design for two outcomes at once, **secure** and **functional**. An API that is secure but too hard to finish a task with sends its users to Stack Overflow or a model for a footgun. (Keyczar produced the most secure solutions of five libraries tested, and the fewest working ones.)

## The ladder

Ranks the ways a rule can be enforced, best first. Put every rule on the highest rung you can reach. Adapted from Rusty Russell's hard-to-misuse scale.

1. **Impossible to get wrong.** The wrong thing cannot be expressed: there is no nonce parameter to reuse.
2. **Won't compile.**
3. **Fails the build**: a `deny`-level lint, a compile-fail test, a conformance check that runs before merge. A warning that nothing denies is read once, then tuned out (Vance 2018), so it counts as rung 7.
4. **The simplest use is correct**: the default is secure.
5. **The name says how to use it**: `risky_unwrap`, a `hazmat` module.
6. **Fails loudly at runtime**, on first use.
7. **Documented.**
8. **Documented, but the obvious use is wrong.** A footgun.

Below rung 6, a mistake ships silently. Treat rungs 7 and 8 as bugs to fix.

This skill is rung 7. Every rule it enforces only by text is one a mistake can ship past. Treat it as a stopgap. Where it tells a caller to avoid something the API allows, raise that item into the API or into CI. Then delete the sentence.

## Rules

Each rule states the target. The studies behind each are in [EVIDENCE.md](EVIDENCE.md).

1. **Secure by default.** The zero-configuration call is the secure call. Callers choose an algorithm, mode, nonce, IV, padding or key size only when the task genuinely needs it, and then every choice offered is safe.
2. **Offer tasks, not primitives.** Name operations for what the caller is doing ("encrypt this record for this tenant"). Primitives live in a lower, clearly named layer.
3. **Own the periphery.** The library provides, typed, everything a caller would otherwise improvise: key generation, key loading and storage, randomness, nonces, password-based derivation, secret comparison, encoding, and wiping. A secure core call fed an improvised input is still a vulnerability, and this is where most real failures are.
4. **Make secrets a type.** A secret lives in a type that wipes on drop, prints opaquely, compares in constant time if at all, and leaves only through a named, greppable escape hatch.
5. **Make invalid states unrepresentable.** Parse once into a type that proves validity (key length, non-empty context, verified signature, authenticated ciphertext) and accept only that type.
6. **Promise only what you deliver.** Names and types claim exactly the guarantee provided. Where a guarantee stops (an AEAD that does not commit to its key, a position that is not authenticated), say so at the type, where the caller looks.
7. **Errors reveal nothing.** Errors never carry plaintext, keys or secret-derived values. Cryptographic failures are one opaque error: a wrong key, a wrong AAD and tampering look the same. Context comes from paths and positions.
8. **Warn at the point of use.** A footgun that cannot be removed (a legacy algorithm, a compatibility mode) warns when used, or requires an explicit opt-in. A warning carries a classification, a title, the code location, and a link to the secure alternative. Keep warnings rare and specific so they are not tuned out. Escape hatches are obvious but effortful: a named feature, a `hazmat` module, a `risky_` prefix. Every escape hatch has an allowlist of call sites that CI enforces: a new use fails CI until a reviewer adds it with a reason. The length of that list is the residual risk, so count it per release.
9. **Every example is secure and complete.** Each example is the production path, inputs included: real key generation, real randomness, real error handling. An example labelled "insecure, for illustration" is copied anyway, so publish only secure ones. Compile-check every example in CI, and use `todo!()` for anything elided so a copied snippet fails loudly.
10. **Keep it small.** Fewer features, options and dependencies. Complexity tracks vulnerability count.
11. **Evolve loudly.** Deprecations name their replacement, and migrations are mechanical. A breaking change is acceptable when the upgrade path is smooth. Finish every migration by denying the old path (rung 3), so it cannot return. Anything left on it is an exemption on the allowlist, not the default.

When rules conflict with each other or with other goals (flexibility, performance, `no_std`), name the trade-off, choose explicitly, and record the choice where reviewers will find it: an ADR or the type's doc comment.

## Designing an API

1. Write the invariant each type will guarantee, in one sentence a reviewer can test ("every `Verified<Issuer>` passed a signature check under the issuer's key"). A type with no stated invariant cannot be checked against rule 6.
2. Write the task as the caller would state it, then list every input the caller must supply.
3. For each input, list its footguns: wrong source, wrong length, reuse, leaking through logs, `Debug` or errors, non-constant-time comparison, accidental serialisation, wrong order of steps.
4. Place each footgun on the ladder, then raise it as far as it will go. Removing the input altogether (rule 3) beats every other rung. What cannot be raised in the API gets a CI check (rung 3), not a sentence in the docs.
5. Write the caller's secure example before the implementation. If it is longer or harder than the insecure code a caller could write with other tools, simplify the API until it is not.
6. List what the change adds: public items, options, features, dependencies, lines. For each, say why it cannot be removed (rule 10).
7. Add a compile-fail test for every rung-2 guarantee, a CI check for every rung-3 one, and a test for every rung-6 refusal.

Done when every caller-supplied input has its footgun list, every footgun sits on rung 6 or higher, and each has a test. Also count the residual: record the number of `risky_*` call sites, `unsafe` blocks and allowlist exemptions per release. That number must not rise.

## Reviewing an API or change

Check every public item in scope (type, function, trait, feature flag, example, doc comment) against all eleven rules. For each finding, report: the item, the rule, the rung it sits on now, the rung it could reach, and the concrete misuse (these inputs lead to this insecure outcome). Before reporting a finding, check the project's ADRs and design notes: a documented, deliberate trade-off is not a footgun. Also report every new `unsafe` block, `#[allow]` or `risky_*` call site the change adds, as a finding. Each needs a reason on the allowlist, or it blocks the change.

Done when every public item in scope has been checked against every rule, with items that have no findings listed as such. Every finding that cannot be raised in the API names the CI check that will catch it instead. A review that ends in prose only has left the item on rung 7.

## Rust and vitaminc

For Rust techniques at each rung (newtypes, typestate, sealed traits, const generics, withheld traits, compile-fail tests, the assumptions behind "if it compiles, it is secure"), read [RUST.md](RUST.md).

In Rust, the vitaminc crates provide ready-made types for rules 3, 4 and 5: secret wrappers, randomness, encryption, key wrapping and keyed hashing. Reach for them before writing your own. The `vitaminc` skill shows how to use them. It is installed here, at `.claude/skills/vitaminc/`.
