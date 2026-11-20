# Transcript audit: flags read by hand

`harness/run_evaluation.py` audits every tool call in every evaluator transcript, and
`harness/reaudit.py` re-applies the current rules to finished runs. The audit is deliberately loose: it
flags any tool input that mentions something network-like (`https://`, `curl`, `gh <cmd>`, `npm view`,
`git fetch`, …) or a path outside the case directory. Each remaining flag was read in full.

**Result: no evaluator made a network request or read outside its case.** Every flag is one of three
harmless patterns:

| Pattern | Runs | What the call actually was |
|---|---|---|
| Writing `assessment.json` with a Bash heredoc | B/1088, C/503, C/568, C/982 | `cat > /srv/cr/<case>/out/assessment.json <<'EOF'`. The JSON contains URLs from the PR (for example the repository URL). The file write is local |
| Searching the checkout for workflow text | A/941 (×2), B/941, B/1026, C/1026 (×2) | `grep`, `git grep`, `git show <sha>:<path> \| grep` or the Grep tool inside `/srv/cr/<case>/repo`, with patterns such as `gh workflow run` or `gh release`. The workflow files contain these strings; nothing was executed |
| Searching source with a long regex | C/996 (×3) | `git grep -nE` / `git show` over the case repository; the pattern text tripped the network heuristic |

Isolation does not rest on this audit. Each evaluator also ran in a private mount namespace with this
directory, the orchestrating session and all session transcripts hidden, git restricted to the `file`
protocol, MCP disabled, and WebFetch/WebSearch disallowed (`research/methodology.md` §2). The audit
checks that those controls held. It does not replace them.

Regenerate the list with `python3 harness/reaudit.py`.
