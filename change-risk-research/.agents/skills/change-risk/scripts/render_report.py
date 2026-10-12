#!/usr/bin/env python3
"""Render a change-risk assessment JSON as a short Markdown report.

    render_report.py assessment.json [--out report.md]

The report is derived only from the JSON, so the two cannot disagree.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

READINESS = {
    "ready_for_review": "Ready for normal review",
    "focused_review_required": "Focused review required",
    "changes_or_verification_required": "Changes or verification required",
    "insufficient_evidence": "Insufficient evidence to assess",
}


def ref(e: dict) -> str:
    if e.get("path"):
        loc = e["path"]
        if e.get("line_start"):
            loc += f":{e['line_start']}" + (f"-{e['line_end']}" if e.get("line_end", e["line_start"]) != e["line_start"] else "")
        return f"`{loc}`" + (" (base)" if e.get("rev") == "base" else "")
    if e.get("signal"):
        return f"signal `{e['signal']}`"
    if e.get("command"):
        return f"`{e['command']}`"
    return e["kind"]


def render(a: dict) -> str:
    ev = {e["id"]: e for e in a["evidence"]}
    comps = {c["id"]: c["name"] for c in a["affected_components"]}
    out = [
        f"## Change risk: {READINESS[a['release_readiness']]}",
        "",
        f"**Impact if something goes wrong:** {a['impact']} · **Verification confidence:** {a['verification_confidence']} · "
        f"`{a['base_sha'][:10]}..{a['head_sha'][:10]}`",
        "",
        a["summary"],
        "",
    ]
    if a["failure_scenarios"]:
        out += ["### Failure scenarios", ""]
        for fs in a["failure_scenarios"]:
            basis = {"observed_defect": "observed in the code", "plausible_failure": "plausible", "speculative": "speculative"}[fs["basis"]]
            out += [
                f"**{fs['id']} · {fs['title']}** ({fs['impact']} impact, {basis})",
                "",
                f"- Trigger: {fs['trigger']}",
                f"- Mechanism: {fs['mechanism']}",
                f"- Consequence: {fs['consequence']}",
                f"- Affects: {', '.join(comps.get(c, c) for c in fs['affected_components']) or 'not determined'}",
                "- Evidence: " + "; ".join(
                    f"{ref(ev[e])}{'' if ev[e]['status'] == 'verified' else ' (inferred)'}" for e in fs["evidence"] if e in ev
                ),
            ]
            if fs["existing_verification"]:
                out.append("- Existing verification: " + "; ".join(f"{v['description']} [{v['status']}]" for v in fs["existing_verification"]))
            if fs["missing_verification"]:
                out.append("- Missing verification: " + "; ".join(fs["missing_verification"]))
            out += [f"- Mitigation: {fs['mitigation']}", ""]
    else:
        out += ["No material failure scenarios identified.", ""]
    if a["recommended_controls"]:
        out += ["### Recommended controls", ""]
        out += [f"- {rc['description']} ({rc['kind']}; {', '.join(rc['addresses'])})" for rc in a["recommended_controls"]]
        out.append("")
    if a["coverage_limitations"]:
        out += ["### What this assessment could not see", ""]
        out += [f"- {cl['description']} {cl['effect']}" for cl in a["coverage_limitations"]]
        out.append("")
    unavailable = [k for k, v in a["inputs"].items() if v["status"] == "unavailable"]
    if unavailable:
        out += [f"_Inputs unavailable: {', '.join(unavailable)}._", ""]
    out.append(f"_Advisory only. {a['assessor']['agent']} · {a['assessor']['model']} · change-risk {a['assessor']['skill_version']}._")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assessment")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    text = render(json.loads(Path(args.assessment).read_text()))
    if args.out:
        Path(args.out).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
