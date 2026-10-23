#!/usr/bin/env python3
"""Render a change-risk assessment JSON as a short Markdown report.

    render_report.py assessment.json [--out report.md]

The report is derived only from the JSON, so the two cannot disagree.
Every model-written string is untrusted: it may come from a pull request the
assessor read. Prose passes through text(), which keeps it on one line and
neutralises Markdown, HTML and @-mentions; identifiers such as paths and
commands are shown as code spans through code().
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

READINESS = {
    "ready_for_review": "Ready for normal review",
    "focused_review_required": "Focused review required",
    "changes_or_verification_required": "Changes or verification required",
    "insufficient_evidence": "Insufficient evidence to assess",
}


# Inline-significant characters only: text() never starts a line, so block
# markers (#, -, +, =, digits) cannot open a heading or a list.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~])")


def text(s: str) -> str:
    """Untrusted prose as inert inline Markdown: one line, no markup, no mentions."""
    s = " ".join(str(s).split())
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = _MD_SPECIAL.sub(r"\\\1", s)
    return s.replace("@", "@\u200b")  # a zero-width space stops GitHub mention and team pings


def code(s: str) -> str:
    """Untrusted identifier as a code span: fenced by a backtick run longer than any inside."""
    s = " ".join(str(s).split())
    fence = "`" * (max((len(r) for r in re.findall(r"`+", s)), default=0) + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def ref(e: dict, assessment: dict | None = None) -> str:
    if e.get("path"):
        loc = e["path"]
        if e.get("line_start"):
            loc += f":{e['line_start']}" + (f"-{e['line_end']}" if e.get("line_end", e["line_start"]) != e["line_start"] else "")
        label = code(loc) + (" (base)" if e.get("rev") == "base" else "")
        if assessment:
            sha = assessment["base_sha" if e.get("rev") == "base" else "head_sha"]
            url = f"https://github.com/{assessment['repository']}/blob/{sha}/{quote(e['path'], safe='/')}"
            if e.get("line_start"):
                url += f"#L{e['line_start']}"
                if e.get("line_end", e["line_start"]) != e["line_start"]:
                    url += f"-L{e['line_end']}"
            return f"[{label}](<{url}>)"
        return label
    if e.get("signal"):
        return f"signal {code(e['signal'])}"
    if e.get("command"):
        return code(e["command"])
    return e["kind"]


def render(a: dict) -> str:
    ev = {e["id"]: e for e in a["evidence"]}
    comps = {c["id"]: text(c["name"]) for c in a["affected_components"]}
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    main = sorted((fs for fs in a["failure_scenarios"] if fs["basis"] != "speculative"),
                  key=lambda fs: -rank[fs["impact"]])
    hypotheses = [fs for fs in a["failure_scenarios"] if fs["basis"] == "speculative"]
    # The headline is the worst material scenario; a hypothesis that would be
    # worse is named beside it so the two never read as one claim.
    material = max((rank[fs["impact"]] for fs in main), default=1)
    louder = [fs for fs in hypotheses if rank[fs["impact"]] > max(material, rank.get(a["impact"], 0))]
    if louder:
        worst = max(louder, key=lambda fs: rank[fs["impact"]])
        hedge = f" (plus an unconfirmed hypothesis of {worst['impact']} potential impact, {worst['id']}, below)"
    else:
        hedge = ""
    out = [
        f"## Change risk: {READINESS[a['release_readiness']]}",
        "",
        f"**Impact if something goes wrong:** {a['impact']}{hedge} · **Verification confidence:** {a['verification_confidence']} · "
        f"`{a['base_sha'][:10]}..{a['head_sha'][:10]}`",
        "",
        text(a["summary"]),
        "",
    ]
    if a.get("readiness_justification"):
        out += ["**Why normal review is adequate:** " + text(a["readiness_justification"]), ""]
    if main:
        out += ["### Failure scenarios", ""]
        for fs in main:
            basis = {"observed_defect": "observed in the code", "plausible_failure": "plausible", "speculative": "speculative"}[fs["basis"]]
            out += [
                f"**{fs['id']} · {text(fs['title'])}** ({fs['impact']} impact, {basis})",
                "",
                f"- Trigger: {text(fs['trigger'])}",
                f"- Mechanism: {text(fs['mechanism'])}",
                f"- Consequence: {text(fs['consequence'])}",
                f"- Affects: {', '.join(comps.get(c, c) for c in fs['affected_components']) or 'not determined'}",
                "- Evidence: " + "; ".join(
                    f"{ref(ev[e], a)}{'' if ev[e]['status'] == 'verified' else ' (inferred)'}" for e in fs["evidence"] if e in ev
                ),
            ]
            if fs["existing_verification"]:
                out.append("- Existing verification: " + "; ".join(f"{text(v['description'])} \\[{v['status']}\\] (" + "; ".join(ref(ev[e], a) for e in v["evidence"] if e in ev) + ")" for v in fs["existing_verification"]))
            if fs["missing_verification"]:
                out.append("- Missing verification: " + "; ".join(text(m) for m in fs["missing_verification"]))
            out += [f"- Mitigation: {text(fs['mitigation'])}", ""]
    else:
        out += ["No material failure scenarios identified.", ""]
    if a["coverage_limitations"] or hypotheses:
        out += ["### Coverage limitations and questions", ""]
        out += [f"- {text(cl['description'])} {text(cl['effect'])}" for cl in a["coverage_limitations"]]
        for fs in hypotheses:
            refs = "; ".join(ref(ev[e], a) for e in fs["evidence"] if e in ev)
            out.append(f"- **Hypothesis {fs['id']} ({fs['impact']} potential impact): {text(fs['title'])}** "
                       f"If {text(fs['trigger'])} {text(fs['mechanism'])} Consequence, unconfirmed: {text(fs['consequence'])} "
                       f"Evidence: {refs}. Resolve by: {text(fs['mitigation'])}")
        out.append("")
    out += ["### Review checklist", ""]
    if a["recommended_controls"]:
        out += [f"- [ ] {text(rc['description'])} ({', '.join(rc['addresses'])})" for rc in a["recommended_controls"]]
    elif main:
        out += [f"- [ ] {text(fs['mitigation'])} ({fs['id']})" for fs in main]
    else:
        out += ["- [ ] Review the changed contract and coverage limitations in normal review."]
    out.append("")
    unavailable = [k for k, v in a["inputs"].items() if v["status"] == "unavailable"]
    if unavailable:
        out += [f"_Inputs unavailable: {', '.join(unavailable)}._", ""]
    asr = a["assessor"]
    out.append(f"_Advisory only. {text(asr['agent'])} · {text(asr['model'])} · change-risk {text(asr['skill_version'])}._")
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
