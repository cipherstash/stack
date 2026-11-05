# Evals

`cases.json` holds the ten development cases from the `cipherstash/stack` study, each with the revision
pair, the expected impact, whether more than routine review was warranted, and the match criteria for
known defects. Use them as regression checks when changing the skill:

1. Check out the head revision in an isolated clone (only the head's ancestry; see
   `change-risk-research/harness/prepare_case.py` in the source repository).
2. Run the skill and validate the output with `scripts/validate-assessment`.
3. Compare: does any scenario meet a defect's `match_criteria`, is the impact within one level, and
   does the verdict ask for attention where `attention` is true?

These cases are not a benchmark. They were used to try the skill, so results on them are optimistic.
Held-out results are in `change-risk-research/eval/comparison.md`.

Never copy this directory into the checkout an assessor reads: it contains the answers.
