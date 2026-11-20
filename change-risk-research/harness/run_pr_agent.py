#!/usr/bin/env python3
"""Run PR-Agent (plain-diff mode) on corpus cases. Needs an approved LLM provider key.

    run_pr_agent.py --pr N [--pr N ...] --model anthropic/claude-opus-5-5 \
        [--pr-agent /path/to/venv/bin/python] [--work /srv/cr-qodo]

For each case: build the isolated checkout at head (prepare_case.py, condition A),
run `python -m pr_agent.cli --diff-file changes.diff --output review.md
--json-output review.json review` from inside that checkout so PR-Agent can read
full files, and save output, stderr and metadata to eval/qodo/results/<case>/.
The provider key comes from the environment (e.g. ANTHROPIC__KEY or OPENAI__KEY,
PR-Agent's own variable names); it is never written to disk.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINNED = "330f0813b5fe0d1f54b794077c2d02aa85a1fb63"


def run(pr: int, model: str, python: str, work: Path, results: Path) -> dict:
    case_dir = work / f"stack-{pr}"
    subprocess.run([sys.executable, str(ROOT / "harness/prepare_case.py"), "--pr", str(pr), "--condition", "A",
                    "--dest", str(case_dir)], check=True, capture_output=True)
    shutil.copy(ROOT / "eval/qodo/pr_agent.toml", case_dir / "pr_agent.toml")
    out = results / f"stack-{pr}"
    out.mkdir(parents=True, exist_ok=True)
    cmd = [python, "-m", "pr_agent.cli", f"--extra_config_url={case_dir / 'pr_agent.toml'}",
           "--diff-file", str(case_dir / "changes.diff"), "--output", str(out / "review.md"),
           "--json-output", str(out / "review.json"), "review", f"--config.model={model}",
           f"--config.fallback_models=[\"{model}\"]"]
    started = dt.datetime.now(dt.timezone.utc)
    p = subprocess.run(cmd, cwd=case_dir / "repo", capture_output=True, text=True, timeout=1800)
    secs = (dt.datetime.now(dt.timezone.utc) - started).total_seconds()
    (out / "stderr.txt").write_text(p.stderr[-200000:])
    meta = {"case": f"stack-{pr}", "pr_agent_commit": PINNED, "model": model, "exit_code": p.returncode,
            "wall_seconds": secs, "started": started.isoformat(), "cwd": "isolated checkout at head (full-file context)",
            "command": " ".join(cmd[1:])}
    if (out / "review.json").exists():
        meta["usage"] = json.loads((out / "review.json").read_text()).get("usage")
    (out / "run.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr", type=int, action="append", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--pr-agent", default="/tmp/claude-0/pra-main/bin/python")
    ap.add_argument("--work", default="/srv/cr-qodo")
    ap.add_argument("--results", default=str(ROOT / "eval/qodo/results"))
    a = ap.parse_args()
    if not any(k.endswith("__KEY") or k.endswith("_API_KEY") for k in os.environ):
        print("no provider key in the environment; nothing run", file=sys.stderr)
        return 2
    for pr in a.pr:
        print(json.dumps(run(pr, a.model, a.pr_agent, Path(a.work), Path(a.results))), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
