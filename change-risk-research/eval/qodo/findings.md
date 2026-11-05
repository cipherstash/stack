# PR-Agent (Qodo): not run

PR-Agent was researched and configured (`research/qodo.md`) but not run on the corpus. Running it sends
each PR's diff to an LLM provider chosen in its configuration, and the handover requires approval before
repository content goes to a model or SaaS provider that has not been approved. That approval has not
been given, so there are no PR-Agent results, and none have been estimated or substituted.

To run it once a provider is approved, use the same holdout cases and score its `failure_modes` with the
same labels (`harness/score_results.py`). Its `risk_level` maps onto the attention verdict as
`medium` or `high` → attention.
