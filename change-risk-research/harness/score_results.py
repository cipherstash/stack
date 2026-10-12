#!/usr/bin/env python3
"""Score evaluator outputs against ground truth using recorded adjudications.

    score_results.py [--split holdout] [--out eval/results-summary.json]

Inputs
  eval/corpus.json, eval/ground-truth/<pr>.json
  eval/adjudication/<evaluator>/<case>.json  one file per assessed case:
    {"case": "stack-301", "evaluator": "change-risk/C", "run": 1,
     "overall_impact": "high" | null,          # evaluator's overall impact, if it gives one
     "attention": true | false | null,         # did the evaluator ask for more than routine review?
     "findings": [{"id": "FS-1", "label": "match" | "valid" | "unsupported" | "incorrect" | "trivial",
                   "matches": ["KD-1"], "evidence_ok": true | false | null, "actionable": true | false | null,
                   "note": "..."}],
     "cost_usd": 1.2, "wall_seconds": 150}

Labels (pre-registered in research/methodology.md):
  match        same mechanism and consequence class as a known defect
  valid        not a known defect, but plausible, attributable to this change, and supported by the code
  unsupported  mechanism not supported by the cited code, or attribution to this change not shown
  incorrect    factually wrong about what the code does, or pre-existing and not caused by the change
  trivial      true but immaterial to release risk
"""

from __future__ import annotations

import argparse
import collections
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEVEL = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 3), round(min(1.0, c + h), 3)]


def prop(k: int, n: int) -> dict:
    return {"k": k, "n": n, "value": round(k / n, 3) if n else None, "ci95": wilson(k, n)}


def weighted_kappa(pairs: list[tuple[int, int]], k: int = 4) -> float | None:
    if len(pairs) < 2:
        return None
    n = len(pairs)
    obs = [[0] * k for _ in range(k)]
    for a, b in pairs:
        obs[a][b] += 1
    ra = [sum(obs[i]) for i in range(k)]
    rb = [sum(obs[i][j] for i in range(k)) for j in range(k)]
    w = [[(i - j) ** 2 / (k - 1) ** 2 for j in range(k)] for i in range(k)]
    o = sum(w[i][j] * obs[i][j] for i in range(k) for j in range(k)) / n
    e = sum(w[i][j] * ra[i] * rb[j] for i in range(k) for j in range(k)) / (n * n)
    return None if e == 0 else round(1 - o / e, 3)


def score(evaluator_dir: Path, gt: dict, cases: dict, split: str | None, post_hoc: bool = False) -> dict:
    adj = [json.loads(p.read_text()) for p in sorted(evaluator_dir.glob("*.json"))]
    adj = [a for a in adj if split is None or cases[a["case"]]["split"] == split]
    labels = collections.Counter()
    per_case_unsupported = []
    kd_total = kd_hit = 0
    defect_cases = defect_cases_hit = 0
    hi_cases = hi_attended = 0
    low_cases = low_overflag = 0
    impact_pairs = []
    ev_ok = ev_n = act_ok = act_n = 0
    cost = []
    secs = []
    for a in adj:
        g = gt[cases[a["case"]]["pr"]]
        fs = a["findings"]
        for f in fs:
            labels[f["label"]] += 1
            if f.get("evidence_ok") is not None and f["label"] != "trivial":
                ev_n += 1
                ev_ok += bool(f["evidence_ok"])
            if f.get("actionable") is not None and f["label"] in ("match", "valid"):
                act_n += 1
                act_ok += bool(f["actionable"])
        per_case_unsupported.append(sum(f["label"] in ("unsupported", "incorrect") for f in fs))
        kds = {k["id"] for k in g["known_defects"] if post_hoc or not k.get("added_post_hoc")}
        hit = {m for f in fs if f["label"] == "match" for m in f.get("matches", [])}
        if post_hoc:
            hit |= {m for f in fs if f["label"] in ("match", "valid") for m in f.get("post_hoc_matches", [])}
        hit &= kds
        kd_total += len(kds)
        kd_hit += len(hit)
        if g["outcome"] == "defect":
            defect_cases += 1
            defect_cases_hit += bool(hit)
        if g["expert_impact"] in ("high", "critical"):
            hi_cases += 1
            oi = a.get("overall_impact")
            hi_attended += bool(a.get("attention")) and (oi is None or LEVEL.get(oi, -1) >= 2)
        if g["expert_impact"] == "low":
            low_cases += 1
            low_overflag += LEVEL.get(a.get("overall_impact") or "", -1) >= 2
        if a.get("overall_impact") in LEVEL:
            impact_pairs.append((LEVEL[g["expert_impact"]], LEVEL[a["overall_impact"]]))
        if a.get("cost_usd") is not None:
            cost.append(a["cost_usd"])
        if a.get("wall_seconds") is not None:
            secs.append(a["wall_seconds"])
    total = sum(labels.values())
    material = total - labels["trivial"]
    good = labels["match"] + labels["valid"]
    exact = sum(1 for e, o in impact_pairs if e == o)
    within = sum(1 for e, o in impact_pairs if abs(e - o) <= 1)
    return {
        "cases": len(adj),
        "findings": total,
        "findings_per_case": round(total / len(adj), 2) if adj else None,
        "labels": dict(labels),
        "scenario_precision_all": prop(good, total),
        "scenario_precision_material": prop(good, material),
        "known_defect_recall": prop(kd_hit, kd_total),
        "defect_case_recall": prop(defect_cases_hit, defect_cases),
        "high_impact_attention": prop(hi_attended, hi_cases),
        "false_positive_burden_per_case": round(sum(per_case_unsupported) / len(adj), 2) if adj else None,
        "low_impact_overflag": prop(low_overflag, low_cases),
        "impact_exact_agreement": prop(exact, len(impact_pairs)),
        "impact_within_one": prop(within, len(impact_pairs)),
        "impact_weighted_kappa": weighted_kappa(impact_pairs),
        "evidence_quality": prop(ev_ok, ev_n),
        "actionability": prop(act_ok, act_n),
        "cost_usd": {"mean": round(sum(cost) / len(cost), 2) if cost else None, "total": round(sum(cost), 2), "n": len(cost)},
        "wall_seconds": {"mean": round(sum(secs) / len(secs), 1) if secs else None, "n": len(secs)},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=("dev", "holdout"), default=None)
    ap.add_argument("--adjudication", default=str(ROOT / "eval" / "adjudication"))
    ap.add_argument("--out", default=None)
    ap.add_argument("--include-post-hoc", action="store_true",
                    help="also count known defects added to ground truth after scoring began (not pre-registered)")
    args = ap.parse_args()
    corpus = json.loads((ROOT / "eval" / "corpus.json").read_text())
    cases = {c["id"]: c for c in corpus["cases"]}
    gt = {int(p.stem): json.loads(p.read_text()) for p in (ROOT / "eval" / "ground-truth").glob("*.json")}
    out = {}
    for d in sorted(Path(args.adjudication).glob("*/*")):
        if d.is_dir():
            out[f"{d.parent.name}/{d.name}"] = score(d, gt, cases, args.split, args.include_post_hoc)
    text = json.dumps({"split": args.split or "all", "post_hoc_defects": args.include_post_hoc, "evaluators": out}, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
