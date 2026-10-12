## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `9bf2a56778..7744caf8fe`

A one-line documentation fix in the repository-root AGENTS.md (imported by CLAUDE.md) that changes the documented auth-strategy config key from `config.strategy` to `config.authStrategy`. The new text matches the code at head: `ClientConfig.authStrategy` is the current field and `strategy` is a deprecated alias that still works but logs a warning. AGENTS.md is agent guidance for contributors to this monorepo; the root package is private and nothing found packages or ships this file. No runtime, contract or release behaviour changes. No material failure scenario was found; the change reduces drift between agent guidance and the API.

No material failure scenarios identified.

### What this assessment could not see

- No CI results or PR description were available, and no tests were run. The documentation claim was checked by reading the type definition, the alias resolution code and the existing tests at head. Confidence rests on reading the source, not on executed checks. For a one-line doc change this does not change the conclusion.
- Packaging was checked by confirming the root package.json is private and that no package.json or workflow under .github references AGENTS.md. Publish tooling outside these paths was not examined. If some unexamined process copies the root AGENTS.md into a published artefact, the change would reach customers. It would still be a correction, so the risk does not go up.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
