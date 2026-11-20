#!/usr/bin/env python3
"""Pin every selected PR to its review-time revisions and write eval/corpus.json.

    build_corpus.py --repo ../ [--selection eval/selection.json] [--out eval/corpus.json]

Review-time reconstruction: for a PR merged with a merge commit M whose parents
are P1 (base branch tip at merge) and P2 (the PR head), the comparison GitHub
showed reviewers is the three-dot diff merge-base(P1, P2)..P2. That is what each
case pins. It is exact for the final head; earlier review rounds of a PR that was
updated after review are not reconstructed, and the case says so.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gitutil import commit_date, git, numstat, pr_merges  # noqa: E402

LANG = {".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript", ".js": "JavaScript",
        ".mjs": "JavaScript", ".cjs": "JavaScript", ".rs": "Rust", ".go": "Go", ".sql": "SQL", ".sh": "Shell",
        ".yml": "YAML", ".yaml": "YAML", ".py": "Python"}


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(here.parent))
    ap.add_argument("--ref", default="origin/main")
    ap.add_argument("--selection", default=str(here / "eval" / "selection.json"))
    ap.add_argument("--out", default=str(here / "eval" / "corpus.json"))
    args = ap.parse_args()
    sel = json.loads(Path(args.selection).read_text())
    merges = {m.number: m for m in pr_merges(args.repo, args.ref)}
    cases = []
    for c in sel["cases"]:
        m = merges[c["pr"]]
        rows = numstat(args.repo, m.merge_base, m.head_sha)
        langs = collections.Counter(LANG.get(Path(p).suffix, "other") for _, _, p in rows)
        n_commits = len(git(args.repo, "rev-list", f"{m.merge_base}..{m.head_sha}").split())
        cases.append(
            {
                "id": f"stack-{c['pr']}",
                "repository": sel["repository"],
                "pr": c["pr"],
                "url": f"https://github.com/{sel['repository']}/pull/{c['pr']}",
                "title": m.title,
                "split": c["split"],
                "subsystem": c["subsystem"],
                "categories": c["categories"],
                "outcome_class": c["outcome"],
                "base_sha": m.merge_base,
                "head_sha": m.head_sha,
                "merge_sha": m.merge_sha,
                "base_branch_tip_at_merge": m.base_parent,
                "base_date": commit_date(args.repo, m.merge_base),
                "merged_at": m.merged_at,
                "pr_commits": n_commits,
                "files_changed": len(rows),
                "additions": sum(a or 0 for a, _, _ in rows),
                "deletions": sum(d or 0 for _, d, _ in rows),
                "languages": dict(langs.most_common()),
                "baseline": "reconstructed: merge-base of the merge commit's parents (GitHub three-dot diff at merge)",
                "baseline_caveat": "final PR head only; review rounds before the last push are not reconstructed",
            }
        )
    out = {
        "schema": "change-risk-research corpus v1",
        "repository": sel["repository"],
        "built_from_ref": git(args.repo, "rev-parse", args.ref).strip(),
        "cases": cases,
        "excluded": sel.get("excluded", []),
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(f"{len(cases)} cases -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
