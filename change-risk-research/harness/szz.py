#!/usr/bin/env python3
"""SZZ-style candidate search: which earlier PRs last touched the lines a fix PR changed?

For a fix PR, take the review-time diff (merge-base..head), find the lines it
deletes or modifies in source files, `git blame` them at the merge-base, and map
each blamed commit to the PR that merged it. The output is a list of CANDIDATE
bug-introducing PRs. It is not ground truth on its own: every candidate is
checked by hand before it is used (see research/methodology.md).

Usage: szz.py --repo PATH --pr N [--pr N ...] [--index prs.json]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gitutil import git, pr_merges  # noqa: E402

SKIP = re.compile(
    r"(^|/)(__tests__|tests?|e2e|docs?|fixtures?)/|\.(md|mdx|snap|lock)$|"
    r"CHANGELOG|pnpm-lock\.yaml$|Cargo\.lock$|\.test\.[cm]?[jt]sx?$|_test\.go$|\.changeset/"
)
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")


def commit_to_pr(repo: Path, merges) -> dict[str, int]:
    owner: dict[str, int] = {}
    # oldest first so a commit is attributed to the first PR that merged it
    for m in sorted(merges, key=lambda m: m.merged_at):
        for sha in git(repo, "rev-list", f"{m.merge_base}..{m.head_sha}").split():
            owner.setdefault(sha, m.number)
    return owner


def removed_lines(repo: Path, base: str, head: str) -> dict[str, list[int]]:
    out: dict[str, list[int]] = collections.defaultdict(list)
    path = None
    for line in git(repo, "diff", "-U0", "-w", "--no-renames", base, head).splitlines():
        if line.startswith("--- "):
            p = line[4:]
            path = None if p == "/dev/null" else p[2:]
        elif line.startswith("@@") and path and not SKIP.search(path):
            mm = HUNK.match(line)
            start, count = int(mm.group(1)), int(mm.group(2) or "1")
            out[path].extend(range(start, start + count))
    return out


def blame(repo: Path, rev: str, path: str, lines: list[int]) -> collections.Counter:
    c: collections.Counter = collections.Counter()
    if not lines:
        return c
    args = ["blame", "-w", "--porcelain", rev]
    for ln in lines:
        args += ["-L", f"{ln},{ln}"]
    out = git(repo, *args, "--", path, check=False)
    for line in out.splitlines():
        if re.match(r"^[0-9a-f]{40} \d+ \d+", line):
            c[line[:40]] += 1
    return c


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--ref", default="origin/main")
    ap.add_argument("--pr", type=int, action="append", required=True)
    args = ap.parse_args()
    repo = Path(args.repo)
    merges = pr_merges(repo, args.ref)
    by_num = {m.number: m for m in merges}
    owner = commit_to_pr(repo, merges)
    report = {}
    for n in args.pr:
        m = by_num[n]
        counts: collections.Counter = collections.Counter()
        files: dict[int, set] = collections.defaultdict(set)
        for path, lines in removed_lines(repo, m.merge_base, m.head_sha).items():
            for sha, k in blame(repo, m.merge_base, path, lines).items():
                pr = owner.get(sha, f"direct:{sha[:10]}")
                counts[pr] += k
                files[pr].add(path)
        report[n] = [
            {"pr": pr, "blamed_lines": k, "files": sorted(files[pr])}
            for pr, k in counts.most_common(8)
        ]
    json.dump(report, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
