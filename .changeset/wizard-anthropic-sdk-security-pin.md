---
"@cipherstash/wizard": patch
---

Add `@anthropic-ai/sdk` `^0.106.0` as a direct dependency so the
auto-installed peer of `@anthropic-ai/claude-agent-sdk` resolves to a release
patched against GHSA-p7fg-763f-g4gf, instead of the vulnerable 0.81.0 the
peer range alone would select. The wizard never imports the SDK directly —
this is a peer-resolution pin only; no behaviour change.
