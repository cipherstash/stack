#!/usr/bin/env python3
"""Build an isolated, outcome-blind case directory for one corpus entry.

    prepare_case.py --pr N --condition {A,B,C} --dest DIR [--repo PATH]

The case directory contains:
  repo/                 a fresh git repository holding ONLY the ancestry of the
                        PR head (fetched by sha, no refs, no remotes), checked
                        out at head. Later commits, including the fix PRs that
                        define ground truth, are not present.
  CASE.md               what to assess, and which inputs exist for this condition
  changes.diff          base..head, full
  evidence.json/.md     deterministic signals (conditions B and C)
  pr-description.md     PR title and body, review-bot output removed (condition C)
  ci.json               check runs on the head commit (condition C)

Conditions (the ablation in the handover, section 6.5):
  A  diff + source checkout + PR title
  B  A + deterministic evidence
  C  B + PR description + CI results
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILL = ROOT / ".agents" / "skills" / "change-risk"


def sh(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def isolated_checkout(src: Path, head: str, dest: Path) -> None:
    sh("git", "init", "-q", str(dest))
    sh("git", "-C", str(dest), "-c", "protocol.file.allow=always", "fetch", "-q", "--no-tags", str(src), head)
    sh("git", "-C", str(dest), "checkout", "-q", "--detach", head)
    (dest / ".git" / "FETCH_HEAD").unlink(missing_ok=True)
    sh("git", "-C", str(dest), "reflog", "expire", "--expire=now", "--all")
    # sanity: nothing after head is reachable or even present
    present = int(sh("git", "-C", str(dest), "rev-list", "--count", "--all"))
    ancestry = int(sh("git", "-C", str(src), "rev-list", "--count", head))
    if present != ancestry:
        raise SystemExit(f"isolation check failed: {present} commits present, {ancestry} in head ancestry")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr", type=int, required=True)
    ap.add_argument("--condition", choices="ABC", required=True)
    ap.add_argument("--dest", required=True)
    ap.add_argument("--repo", default=str(ROOT.parent))
    ap.add_argument("--corpus", default=str(ROOT / "eval" / "corpus.json"))
    args = ap.parse_args()

    corpus = json.loads(Path(args.corpus).read_text())
    case = next(c for c in corpus["cases"] if c["pr"] == args.pr)
    dest = Path(args.dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    src = Path(args.repo)

    isolated_checkout(src, case["head_sha"], dest / "repo")
    (dest / "changes.diff").write_text(sh("git", "-C", str(src), "diff", "-M", case["base_sha"], case["head_sha"]))

    # The skill, installed where Claude Code discovers project skills. Tests excluded.
    skill_dest = dest / ".claude" / "skills" / "change-risk"
    shutil.copytree(SKILL, skill_dest, ignore=shutil.ignore_patterns("tests", "__pycache__", "evals"))

    inputs = {"diff": "changes.diff", "source checkout": "repo/ (at head; base is an ancestor)"}
    if args.condition in "BC":
        for fmt, name in (("json", "evidence.json"), ("md", "evidence.md")):
            sh(sys.executable, str(SKILL / "scripts" / "collect_evidence.py"), "--repo", str(dest / "repo"),
               "--base", case["base_sha"], "--head", case["head_sha"], "--repository", case["repository"],
               "--format", fmt, "--out", str(dest / name))
        inputs["deterministic evidence"] = "evidence.json, evidence.md (collect-evidence, already run)"
    if args.condition == "C":
        desc = ROOT / "eval" / "pr-descriptions" / f"{args.pr}.md"
        ci = ROOT / "eval" / "ci" / f"{args.pr}.json"
        if desc.exists():
            shutil.copy(desc, dest / "pr-description.md")
            inputs["PR description"] = "pr-description.md"
        if ci.exists():
            shutil.copy(ci, dest / "ci.json")
            inputs["CI results"] = "ci.json (check runs on the head commit as GitHub reports them now)"

    lines = [
        f"# Change to assess: {case['repository']}",
        "",
        f"- Title: {case['title']}",
        f"- Base: `{case['base_sha']}`",
        f"- Head: `{case['head_sha']}`",
        f"- Size: {case['files_changed']} files, +{case['additions']}/-{case['deletions']}",
        "",
        "## Inputs available",
        "",
        *[f"- {k}: {v}" for k, v in inputs.items()],
        "",
        "Anything not listed is unavailable. In particular there is no network access, no access to GitHub, "
        "and no history after the head commit.",
    ]
    (dest / "CASE.md").write_text("\n".join(lines) + "\n")
    print(dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
