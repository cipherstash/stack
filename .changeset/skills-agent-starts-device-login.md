---
"stash": patch
---

The `stash-cli` and `stash-auth` skills now tell an agent to start
`stash auth login --json` itself when local work stops on missing
credentials, and to show the user the approval URL, rather than stop, ask for
`CS_*` values, or run `stash env`. They also say how to choose `--region`
instead of guessing it.
