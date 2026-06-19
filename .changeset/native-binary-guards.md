---
"stash": minor
---

Add guards for missing native binaries. When npm skips the platform-specific
optional dependency (a known npm bug), stash now prints actionable fix
guidance instead of a raw `MODULE_NOT_FOUND` stack trace. Adds a new
`stash doctor` command that diagnoses the runtime and native modules and works
even when a binary is missing.
