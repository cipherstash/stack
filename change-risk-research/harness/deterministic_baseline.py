#!/usr/bin/env python3
"""Deterministic-signals baseline: collect evidence for every case and apply a fixed attention rule.

    deterministic_baseline.py [--repo ..]

Writes eval/deterministic/results/<case>.json (full collector output) and
eval/adjudication/deterministic/rule-v1/<case>.json (attention flag; no scenarios).

The rule was fixed before scoring and is deliberately simple. It answers only
"should a human look harder at this?" — the deterministic layer cannot name a
failure scenario, so it gets no precision or recall on scenarios.

attention if ANY of:
  R1  a non-test, non-doc file is classed security_sensitive or serialization_or_protocol
  R2  a database_schema file changes
  R3  a ci_workflow or release_tooling file changes
  R4  a runtime dependency (dependencies/peerDependencies or [dependencies]) changes in a manifest
  R5  the change touches 3 or more components
  R6  an omitted co-change with confidence >= 0.8 and >= 4 co-commits
  R7  more than 400 changed lines in non-test, non-doc, non-lockfile files
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLLECT = ROOT / ".agents/skills/change-risk/scripts/collect_evidence.py"
NOISE = {"test", "docs", "lockfile", "generated"}


def rule(ev: dict) -> list[str]:
    hits = []
    src = [f for f in ev["files"] if not set(f["classes"]) & NOISE]
    if any({"security_sensitive", "serialization_or_protocol"} & set(f["classes"]) for f in src):
        hits.append("R1")
    if any("database_schema" in f["classes"] for f in ev["files"]):
        hits.append("R2")
    if any({"ci_workflow", "release_tooling"} & set(f["classes"]) for f in ev["files"]):
        hits.append("R3")
    for d in ev["dependencies"]:
        if any(x["section"] in ("dependencies", "peerDependencies") for x in d.get("dependencies", [])):
            hits.append("R4")
            break
    if ev["dispersion"]["component_count"] >= 3:
        hits.append("R5")
    if any(c["confidence"] >= 0.8 and c["co_commits"] >= 4 for c in ev["co_change"]["omitted_co_changes"]):
        hits.append("R6")
    if sum((f["additions"] or 0) + (f["deletions"] or 0) for f in src) > 400:
        hits.append("R7")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(ROOT.parent))
    args = ap.parse_args()
    corpus = json.loads((ROOT / "eval/corpus.json").read_text())
    res_dir = ROOT / "eval/deterministic/results"
    adj_dir = ROOT / "eval/adjudication/deterministic/rule-v1"
    res_dir.mkdir(parents=True, exist_ok=True)
    adj_dir.mkdir(parents=True, exist_ok=True)
    for c in corpus["cases"]:
        out = res_dir / f"{c['id']}.json"
        subprocess.run([sys.executable, str(COLLECT), "--repo", args.repo, "--base", c["base_sha"], "--head",
                        c["head_sha"], "--repository", c["repository"], "--out", str(out)], check=True)
        ev = json.loads(out.read_text())
        hits = rule(ev)
        (adj_dir / f"{c['id']}.json").write_text(json.dumps({
            "case": c["id"], "evaluator": "deterministic/rule-v1", "run": 1,
            "overall_impact": None, "attention": bool(hits), "rules_fired": hits, "findings": [],
            "cost_usd": 0.0, "wall_seconds": None}, indent=2) + "\n")
        print(c["id"], c["split"], hits)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
