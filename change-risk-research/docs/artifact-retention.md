# Experimental record and retention

The completion pass preserves every original assessment, ground-truth record and
adjudication. Version-1 metric summaries stay at their original paths; version-2
metrics have new filenames. `eval/record-audit.json` records assessment checksums,
exact base/head revisions, agent/model/skill metadata, and strict-validation results.
Of 119 assessments, 115 pass revision-1.1 schema/semantic validation. Four remain
readable but fail stricter rules (unsubstantiated high verification confidence,
ready-for-review with an observed defect, or an inferred execution claim). The
audit names each error. Repository source evidence was not rechecked for this audit.

## Cleanup and reproduction

Removed nine tracked Python bytecode files (145,475 bytes) and ignored future
`__pycache__`/`.pyc` files. Removed 119 historical `report.md` files (1,039,707 bytes)
only after proving each was byte-for-byte reproducible from its retained assessment
using the original renderer. No distinct rendered output was discarded.
`eval/derived-report-manifest.json` records their original paths, sizes and SHA-256s.
Gross removable content: 1,185,182 bytes, before the new documentation and manifests.
After the new skill refinements, review packet, smoke outputs and audit manifests,
the research and skill tree is approximately 0.9 MB smaller overall.

Restore any original report into a temporary directory without changing the record:

```bash
git show cf0e8b6f41a957fc32a02be83f7c5076fc82a753:change-risk-research/.agents/skills/change-risk/scripts/render_report.py > /tmp/change-risk-render-v1.py
python3 /tmp/change-risk-render-v1.py change-risk-research/eval/change-risk/results/C/stack-547-r1/assessment.json --out /tmp/stack-547-report.md
shasum -a 256 /tmp/stack-547-report.md
```

Compare with the matching entry in the manifest. The current renderer can also
produce a reviewer-friendly report from any historical assessment, without needing
it to pass stricter semantics or rewriting its JSON.

## Unique transcripts: explicit retention decision

Retain all 150 compressed transcripts at their existing Git paths for now. They
are unique (no duplicate compressed checksums) and total 26,443,909 bytes. There is
no approved accessible external archive destination in this task, so moving or
deleting the only audit trail would lose evidence. No upload or publication was
performed. A maintainer can later choose durable storage, verify every checksum
and access permission, and replace the files with that manifest/location in a
separate retention decision. Repository footprint remains dominated by these files.

`harness/audit_record.py` scans decompressed transcripts for common GitHub/provider
keys, AWS IDs, private-key headers and JWT shapes, recording counts without
recording secret values. This pass found zero matches. It is a heuristic credential
check, not proof that transcripts contain no sensitive data; review content and
access requirements before any new archive publication. Existing run metadata,
corpus revisions and transcript initialization records preserve tool/model versions.

The README lists deterministic metric/audit regeneration. Reproducing original
model runs requires the original Linux isolation setup and 1.0 skill; running the
revised skill on the old corpus is a new, holdout-informed experiment. Independent
human validation remains outstanding.
