## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `9bf2a56778..7744caf8fe`

Documentation-only, one-line correction in the repository-root AGENTS.md: the identity-aware-encryption bullet now names the ClientConfig auth-strategy key as `config.authStrategy` instead of `config.strategy`. The head source confirms `authStrategy` is the documented field and `strategy` is a deprecated alias that still works but warns at runtime, so the old text was stale guidance and the new text matches the code. AGENTS.md is not in the published package's `files` list and the root package is private, so nothing shipped to customers changes. No code, tests, build or release configuration change. No material failure scenario was found.

No material failure scenarios identified.

### Recommended controls

- Optional follow-up outside this change: grep shipped agent skills and READMEs for the deprecated `config.strategy` wording, since drift there reaches customers. (documentation; )

### What this assessment could not see

- Other documentation and shipped skills were not exhaustively audited for the same stale key. A head `git grep` for `config.strategy` found it only in CHANGELOG history, tests of the deprecated alias, and the alias-handling source. Similar drift elsewhere is outside this change and would not alter its risk.
- No dependency graph or deployment context was provided. Not relevant to a doc-only change to an unpublished file; no effect on the verdict.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
