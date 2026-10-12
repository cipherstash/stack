"""Small git helpers shared by the harness scripts. Standard library only."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

MERGE_RE = re.compile(r"^Merge pull request #(\d+) from (\S+)")


def git(repo: Path | str, *args: str, check: bool = True) -> str:
    res = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip()}")
    return res.stdout


@dataclass
class PrMerge:
    number: int
    branch: str
    title: str
    merge_sha: str
    base_parent: str  # first parent: the base branch tip at merge time
    head_sha: str  # second parent: the PR head that was merged
    merge_base: str  # merge-base(base_parent, head_sha): review-time comparison base
    merged_at: str  # committer date of the merge commit (ISO 8601)

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def pr_merges(repo: Path | str, ref: str = "origin/main") -> list[PrMerge]:
    """Every 'Merge pull request #N' commit on the first-parent chain of ref."""
    raw = git(
        repo,
        "log",
        "--first-parent",
        "--merges",
        "--format=%x1e%H %P%x1f%cI%x1f%s%x1f%b",
        ref,
    )
    out: list[PrMerge] = []
    for rec in raw.split("\x1e"):
        if not rec.strip():
            continue
        shas, date, subj, body = (rec.split("\x1f") + ["", "", ""])[:4]
        parts = shas.split()
        m = MERGE_RE.match(subj)
        if not m or len(parts) < 3:
            continue
        merge, p1, p2 = parts[0], parts[1], parts[2]
        mb = git(repo, "merge-base", p1, p2).strip()
        title = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
        out.append(
            PrMerge(
                number=int(m.group(1)),
                branch=m.group(2),
                title=title,
                merge_sha=merge,
                base_parent=p1,
                head_sha=p2,
                merge_base=mb,
                merged_at=date.strip(),
            )
        )
    return out


def numstat(repo: Path | str, base: str, head: str) -> list[tuple[int | None, int | None, str]]:
    """(added, deleted, path) per file; None for binary files."""
    rows = []
    for line in git(repo, "diff", "--numstat", "-M", base, head).splitlines():
        a, d, path = line.split("\t", 2)
        if " => " in path:  # rename: keep the new path
            path = re.sub(r"\{[^{}]* => ([^{}]*)\}", r"\1", path)
            if " => " in path:
                path = path.split(" => ")[1]
            path = path.replace("//", "/")
        rows.append((None if a == "-" else int(a), None if d == "-" else int(d), path))
    return rows


def commit_date(repo: Path | str, sha: str) -> str:
    return git(repo, "show", "-s", "--format=%cI", sha).strip()
