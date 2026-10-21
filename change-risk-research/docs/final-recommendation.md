# Recommendation

Adopt the standalone `change-risk` skill for on-demand, evidence-backed PR impact
assessment alongside CodeRabbit. Use human judgement for merge decisions.
[Normal invocation](../README.md) requires only a checkout, revisions (or a PR
resolved with existing GitHub tooling), and an already available agent.

The original 1.0 experiment demonstrated useful behaviour: plausible failure
scenarios, impacted contracts and missing verification. Condition C's adjudicated
material scenario validity was 68/78 (87%) initially and 60/78 (77%) under the second,
evaluator-blinded agent adjudication. These are plausible-scenario judgements,
not confirmed-defect precision. Known-defect recall was 4/11; important defects
were missed. First-adjudication evidence coverage was only 1/78 material findings.
See the [reproducible v2 tables](../eval/comparison.md).

Ground truth and adjudication were agent-produced, with shared model-family and
research-design limitations. Independent human review of the [prepared package](human-review.md)
is still an acceptance step. Effectiveness has not been independently validated
at production scale. The revised 1.1 method has not been evaluated on a fresh
holdout, and must not declare a change safe to merge.

CodeRabbit's historical reviews span intermediate pushes; the skill evaluated
final reconstructed heads. Fixes prompted by earlier reviews make raw recall and
finding-count comparisons unsuitable for superiority claims. The tools appear
complementary; retain CodeRabbit for general code review.

Qodo PR-Agent is dropped: its incremental value does not justify further work.
CodeScene is dropped: it is commercial, there is no additional budget, and useful
history concepts are already represented by the optional deterministic collector.
No further commercial comparison, historical score calibration, paid service,
subscription, or model provider is required.

The [CI design](ci-integration.md) is retained as an inactive proposal only. There
is no shadow-mode rollout, automated comment, required check, or merge-gating
project in this completion pass. Any future activation is a separate decision.
