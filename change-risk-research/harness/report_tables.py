#!/usr/bin/env python3
"""Print the markdown metric tables used in eval/comparison.md.

    report_tables.py [--split holdout]

Two views:
  all      every case each evaluator has an adjudication for (n differs by evaluator)
  paired   only the cases every change-risk condition (A, B, C) completed, so the ablation compares like with like
Also writes eval/results-summary.json (all cases) and eval/results-paired.json.
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from score_results import ROOT, score


def fmt(p: dict) -> str:
    if not p or p.get("n", 0) == 0:
        return "n/a"
    lo, hi = p["ci95"]
    return f"{p['k']}/{p['n']} ({p['value']:.0%}; {lo:.0%}–{hi:.0%})"


ROWS = [
    ("Cases", lambda v: str(v["cases"])),
    ("Findings (per case)", lambda v: f"{v['findings']} ({v['findings_per_case']})"),
    ("Precision, non-trivial findings", lambda v: fmt(v["scenario_precision_material"])),
    ("Known-defect recall", lambda v: fmt(v["known_defect_recall"])),
    ("Defect cases with ≥1 match", lambda v: fmt(v["defect_case_recall"])),
    ("Attention where warranted", lambda v: fmt(v["attention_recall"])),
    ("Attention on expert-low cases", lambda v: fmt(v["low_impact_attention"])),
    ("Attention rate overall", lambda v: fmt(v["attention_rate"])),
    ("High-impact cases rated high+ with attention", lambda v: fmt(v["high_impact_attention"])),
    ("Unsupported + incorrect per case", lambda v: str(v["false_positive_burden_per_case"])),
    ("Impact within one level", lambda v: fmt(v["impact_within_one"])),
    ("Impact exact", lambda v: fmt(v["impact_exact_agreement"])),
    ("Weighted kappa (impact)", lambda v: str(v["impact_weighted_kappa"])),
    ("Actionable (match/valid)", lambda v: fmt(v["actionability"])),
    ("Mean cost USD", lambda v: str(v["cost_usd"]["mean"])),
    ("Mean wall seconds", lambda v: str(v["wall_seconds"]["mean"])),
]


def table(results: dict, order: list[str]) -> str:
    cols = [k for k in order if k in results]
    out = ["| Metric | " + " | ".join(cols) + " |", "|---" * (len(cols) + 1) + "|"]
    for name, f in ROWS:
        out.append(f"| {name} | " + " | ".join(f(results[c]) for c in cols) + " |")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="holdout")
    args = ap.parse_args()
    corpus = json.loads((ROOT / "eval/corpus.json").read_text())
    cases = {c["id"]: c for c in corpus["cases"]}
    gt = {int(p.stem): json.loads(p.read_text()) for p in (ROOT / "eval/ground-truth").glob("*.json")}
    adj = ROOT / "eval/adjudication"
    order = ["change-risk/C", "change-risk/B", "change-risk/A", "coderabbit/original", "deterministic/rule-v1"]
    split = None if args.split == "all" else args.split

    full = {f"{d.parent.name}/{d.name}": score(d, gt, cases, split)
            for d in sorted(adj.glob("*/*")) if d.is_dir()}
    print("## All adjudicated cases\n")
    print(table(full, order))

    sets = [{p.stem for p in (adj / "change-risk" / c).glob("*.json")} for c in "ABC"]
    common = set.intersection(*sets)
    common = {c for c in common if split is None or cases[c]["split"] == split}
    paired = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name in [*(f"change-risk/{c}" for c in "CBA"), "coderabbit/original", "deterministic/rule-v1"]:
            src = adj / name
            dst = Path(tmp) / name
            dst.mkdir(parents=True)
            for c in common:
                if (src / f"{c}.json").exists():
                    shutil.copy(src / f"{c}.json", dst / f"{c}.json")
            paired[name] = score(dst, gt, cases, split)
    print(f"\n## Paired: the {len(common)} {args.split} cases all three conditions completed\n")
    print(table(paired, order))

    (ROOT / "eval/results-summary.json").write_text(json.dumps({"split": args.split, "evaluators": full}, indent=2) + "\n")
    (ROOT / "eval/results-paired.json").write_text(json.dumps({"split": args.split, "cases": sorted(common),
                                                               "evaluators": paired}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
