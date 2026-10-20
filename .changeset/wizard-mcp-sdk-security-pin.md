---
"@cipherstash/wizard": patch
---

Add `@modelcontextprotocol/sdk` `^1.32.0` as a direct dependency so the
auto-installed peer of `@anthropic-ai/claude-agent-sdk` resolves to a release
patched against GHSA-6qxp-vccf-f47h / CVE-2026-104850, instead of the vulnerable
1.29.0 previously locked. The wizard never imports the MCP SDK directly — this
is a peer-resolution pin only; no API change.
