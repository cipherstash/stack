## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `9bf2a56778..7744caf8fe`

Documentation-only, one-line change to the repository-root AGENTS.md: the identity-aware encryption bullet now names the auth-strategy client config key as `config.authStrategy` instead of `config.strategy`. The source at head confirms the correction: `ClientConfig.authStrategy` is the documented field, `config.strategy` is a deprecated alias that still works but logs a warning, and `Encryption()` forwards `config.authStrategy` to protect-ffi. No code, build, test, package or shipped skill is touched; the root AGENTS.md is a contributor/agent-instruction file and is not copied into the published CLI tarball (the shipped doctrine lives in packages/cli/src/commands/init/doctrine). No material failure scenario was found.

No material failure scenarios identified.

### What this assessment could not see

- No CI results were supplied and no tests or doc linters were run. Irrelevant to runtime for a docs-only change; correctness of the new text was checked by reading source rather than by any automated check.
- Packaging of root AGENTS.md was judged from the CLI tsup config and the repo's own description (skills/ and the separate doctrine fragment ship; root AGENTS.md is not referenced by any build step). No package tarball was built or inspected. If some unseen step published root AGENTS.md, the change would still be a correction toward the current API, so the conclusion would not change.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
