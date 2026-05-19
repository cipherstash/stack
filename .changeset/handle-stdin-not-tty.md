---
"stash": patch
---

`stash impl` and `stash plan` no longer hang in non-TTY contexts (CI, pipes, automation harnesses). The agent-target picker previously read from `/dev/tty` and waited forever. You can now pass `--target <claude-code|codex|agents-md|wizard>` to select a handoff target non-interactively, and when neither `--target` nor a TTY is available the command prints a hint and exits cleanly instead of blocking.
