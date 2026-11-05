#!/usr/bin/env python3
"""Re-run the transcript audit over finished runs with the current rules in run_evaluation.audit.

    reaudit.py [results_dir]

Runs started before an audit-rule fix keep the old verdict in run.json; this recomputes it from
transcript.jsonl, keeps the previous result under "audit_previous", and prints every flag that remains
so each one can be read by hand.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_evaluation import ROOT, audit  # noqa: E402


def tool_calls(transcript: Path) -> list[dict]:
    calls = []
    text = gzip.decompress(transcript.read_bytes()).decode() if transcript.suffix == ".gz" else transcript.read_text()
    for line in text.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "assistant":
            for b in ev.get("message", {}).get("content", []):
                if b.get("type") == "tool_use":
                    calls.append({"name": b["name"], "input": b.get("input", {})})
    return calls


def main() -> int:
    results = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "eval/change-risk/results"
    for run_json in sorted(results.glob("*/*/run.json")):
        t = run_json.parent / "transcript.jsonl"
        if not t.exists():
            t = t.with_suffix(".jsonl.gz")
        if not t.exists():
            continue
        meta = json.loads(run_json.read_text())
        new = audit(tool_calls(t))
        if new != meta.get("audit"):
            meta["audit_previous"] = meta.get("audit")
            meta["audit"] = new
            run_json.write_text(json.dumps(meta, indent=2) + "\n")
        for f in new["flags"]:
            print(run_json.parent.relative_to(results), f["tool"], f["why"], f["input"][:200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
