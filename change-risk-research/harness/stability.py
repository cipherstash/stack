#!/usr/bin/env python3
"""Run-to-run stability of condition C on the repeated cases (runs 1-3).

    stability.py

For each repeated case: overall impact, verdict and matched known defects in each run.
Writes eval/stability.json and prints a markdown table.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADJ = ROOT / "eval/adjudication/change-risk"


def main() -> int:
    variants = {1: ADJ / "C", 2: ADJ / "C-r2", 3: ADJ / "C-r3"}
    cases = sorted({p.stem for p in variants[2].glob("*.json")} & {p.stem for p in variants[3].glob("*.json")},
                   key=lambda c: int(c.split("-")[1]))
    rows, agree_impact, agree_verdict, agree_attn = [], 0, 0, 0
    kd_runs = []
    for c in cases:
        runs = [json.loads((variants[r] / f"{c}.json").read_text()) for r in (1, 2, 3)]
        gt = json.loads((ROOT / f"eval/ground-truth/{c.split('-')[1]}.json").read_text())
        kds = [k["id"] for k in gt["known_defects"] if not k.get("added_post_hoc")]
        impacts = [r["overall_impact"] for r in runs]
        verdicts = [r["verdict"] for r in runs]
        attn = [r["attention"] for r in runs]
        matched = [sorted({m for f in r["findings"] if f["label"] == "match" for m in f["matches"]}) for r in runs]
        per_kd = {k: sum(k in m for m in matched) for k in kds}
        kd_runs.extend(per_kd.values())
        agree_impact += len(set(impacts)) == 1
        agree_verdict += len(set(verdicts)) == 1
        agree_attn += len(set(attn)) == 1
        rows.append({"case": c, "expert_impact": gt["expert_impact"], "impact": impacts, "verdict": verdicts,
                     "attention": attn, "matched": matched, "known_defect_hits_of_3": per_kd})
    summary = {
        "cases": len(cases),
        "impact_identical_all_runs": agree_impact,
        "verdict_identical_all_runs": agree_verdict,
        "attention_identical_all_runs": agree_attn,
        "known_defects": len(kd_runs),
        "known_defects_found_in_all_3": sum(v == 3 for v in kd_runs),
        "known_defects_found_in_1_or_2": sum(0 < v < 3 for v in kd_runs),
        "known_defects_never_found": sum(v == 0 for v in kd_runs),
    }
    (ROOT / "eval/stability.json").write_text(json.dumps({"summary": summary, "cases": rows}, indent=2) + "\n")
    print("| Case | Expert | Impact r1/r2/r3 | Attention r1/r2/r3 | Known defects found (of 3 runs) |")
    print("|---|---|---|---|---|")
    for r in rows:
        kd = ", ".join(f"{k} {v}/3" for k, v in r["known_defect_hits_of_3"].items()) or "none known"
        print(f"| #{r['case'].split('-')[1]} | {r['expert_impact']} | {' / '.join(map(str, r['impact']))} | "
              f"{' / '.join('yes' if a else 'no' for a in r['attention'])} | {kd} |")
    print()
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
