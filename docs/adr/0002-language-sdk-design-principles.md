---
status: accepted
date: 2026-10-05
---

# Language SDKs follow one set of design principles

Every language SDK for Stack Encrypt follows [the language SDK design principles](../sdk-design-principles.md).
That document holds the principles.
This ADR records the decision to adopt them, and why.

## The problem

The first Go design mirrored the Rust chain: one `Encrypt` verb, `Using(plan)`, and a `Run(ctx)` call in place of `.await`.
A review found that the shape did not fit Go.
One builder with one `Run` could only return `any`.
A forgotten `Run` compiled and did nothing.
A typing mistake in a field name wrote NULL.

Each of those was fixed in turn, and each fix raised the same questions again.
When does a mistake get found?
What does the user see?
What must be the same in every language, and what can differ?
There was no written answer, so each language SDK would have argued them from the start.

## Decision

We adopt the principles in [`docs/sdk-design-principles.md`](../sdk-design-principles.md).
Eight apply to every language SDK, and thirteen apply to the Go SDK.

The document also fixes two terms.
A binding is the FFI or WASI interface between the engine and a target language.
A language SDK is what users of the target language work with day to day.

When two principles disagree, the document gives the order to apply them in.

## Consequences

- A design for a language SDK is reviewed against the principles, and a departure needs a stated reason.
- The Go SDK generates code, because Go cannot express a type that matches the input in any other way.
  Its users write struct tags and call generated functions, and they never see a plan.
- An SDK in a typed language finds most mistakes before the program runs.
  An SDK in a dynamic language ships rules for the language's type checkers and linters.
- Each language SDK is its own design.
  The principles say what must match between them: the bytes, the words for engine behaviour, and fail-closed behaviour.
- Five questions are open, and the principles document lists them.
  The largest is the approach of the Go policy package.

ADR-0007 in `packages/stack-encrypt/docs/adr/` is the ground for the first principle: an SDK enters the engine through a declaration, and never through a second executor.
