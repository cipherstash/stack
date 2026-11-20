# What the known misses reveal

These are interpretations of the recorded 1.0 evaluation, not new recall results.

| Case | Miss | General limitation | Small method change |
|---|---|---|---|
| [#547](https://github.com/cipherstash/stack/pull/547) | Bundled class identity bypassed encrypted-column detection; filter plaintext crossed the network boundary | Other architectural risks distracted from the actual end-to-end guarantee | Trace a representative sensitive value through input, transformation, encryption, serialization and output; inspect how the protected path is selected |
| [#823](https://github.com/cipherstash/stack/pull/823) | DDL inside dollar-quoted blocks escaped the migration guard | Repository examples did not establish all parser/language semantics | Identify the external format and boundary cases absent from tests |
| [#349](https://github.com/cipherstash/stack/pull/349) | drizzle-kit transformed pre-quoted type names incorrectly | Exact third-party serialization behaviour could not be proved from local source | Establish the versioned external contract through primary documentation or a focused reproduction; otherwise ask for verification |

The analysis method adds these three general investigation prompts, without
case-specific detection rules. A missing external contract is a coverage question,
not automatically a plausible defect. Weak speculation belongs outside main
findings. Historical assessments and ground truth are unchanged. Because these
misses informed 1.1, the original holdout cannot remain an untouched holdout for
that revision. No increased recall is claimed.
