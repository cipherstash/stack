#!/usr/bin/env python3
"""Create adjudication files for change-risk runs, pre-filled with everything but the labels.

    adjudication_skeleton.py --condition C [--run 1]

Reads eval/change-risk/results/<condition>/<case>-r<run>/{assessment.json,run.json} and writes
eval/adjudication/change-risk/<condition>[-r<run>]/<case>.json unless it already exists.
Each finding gets label null; the adjudicator fills label, matches, evidence_ok, actionable, note.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ATTENTION = {"focused_review_required", "changes_or_verification_required", "insufficient_evidence"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--condition", required=True)
    ap.add_argument("--run", type=int, default=1)
    args = ap.parse_args()
    src = ROOT / "eval/change-risk/results" / args.condition
    variant = args.condition if args.run == 1 else f"{args.condition}-r{args.run}"
    dst = ROOT / "eval/adjudication/change-risk" / variant
    dst.mkdir(parents=True, exist_ok=True)
    for d in sorted(src.glob(f"*-r{args.run}")):
        case = d.name.rsplit("-r", 1)[0]
        out = dst / f"{case}.json"
        if out.exists():
            continue
        run = json.loads((d / "run.json").read_text())
        a = json.loads((d / "assessment.json").read_text()) if (d / "assessment.json").exists() else None
        doc = {
            "case": case,
            "evaluator": f"change-risk/{variant}",
            "run": args.run,
            "overall_impact": a["impact"] if a and a["impact"] != "unknown" else None,
            "verdict": a["release_readiness"] if a else "error",
            "verification_confidence": a["verification_confidence"] if a else None,
            "attention": (a["release_readiness"] in ATTENTION) if a else None,
            "valid_output": run.get("validation", {}).get("valid"),
            "findings": [
                {"id": fs["id"], "title": fs["title"], "impact": fs["impact"], "basis": fs["basis"],
                 "label": None, "matches": [], "evidence_ok": None, "actionable": None, "note": ""}
                for fs in (a["failure_scenarios"] if a else [])
            ],
            "cost_usd": run.get("total_cost_usd"),
            "wall_seconds": run.get("wall_seconds"),
        }
        out.write_text(json.dumps(doc, indent=2) + "\n")
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
