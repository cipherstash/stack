#!/usr/bin/env python3
"""Run the change-risk skill on corpus cases with headless Claude Code, blind to outcomes.

    run_evaluation.py --pr N [--pr N ...] --condition C [--model M] [--run 1]
                      [--work /srv/cr] [--results eval/change-risk/results] [--jobs 3]

Each run:
  1. prepare_case.py builds an isolated case directory (no history after head).
  2. `claude -p` runs inside a private mount namespace in which this research
     repository, the scratchpad, and Claude session transcripts are hidden by
     empty tmpfs mounts, so ground truth and later history are unreachable even
     through Bash. Git is limited to the file protocol. MCP servers are off.
  3. The transcript (stream-json), assessment.json, report.md, validator output
     and run metadata (model, cost, tokens, duration, tool calls) are copied
     into results/<condition>/<case>-r<run>/.
  4. The transcript is audited for disallowed tool use (network, other paths).
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HIDE = ["/home/claude/stack", "/tmp/claude-0", "/root/.claude/projects"]

ALLOWED_TOOLS = [
    "Read", "Grep", "Glob", "Write", "Edit", "Skill", "TodoWrite",
    "Bash(git:*)", "Bash(grep:*)", "Bash(rg:*)", "Bash(sed:*)", "Bash(awk:*)", "Bash(ls:*)", "Bash(cat:*)",
    "Bash(head:*)", "Bash(tail:*)", "Bash(wc:*)", "Bash(find:*)", "Bash(sort:*)", "Bash(uniq:*)",
    "Bash(diff:*)", "Bash(jq:*)", "Bash(python3:*)", "Bash(cd:*)", "Bash(echo:*)",
    "Bash(.claude/skills/change-risk/scripts/collect-evidence:*)",
    "Bash(.claude/skills/change-risk/scripts/validate-assessment:*)",
    "Bash(.claude/skills/change-risk/scripts/render-report:*)",
]
DISALLOWED_TOOLS = ["WebFetch", "WebSearch", "Agent", "Task", "NotebookEdit"]

PROMPT = """Use the change-risk skill (.claude/skills/change-risk/SKILL.md) to assess the release risk of the change described in CASE.md.

The repository checkout is ./repo. Run git commands with `git -C repo ...`. Base and head shas are in CASE.md.
Use only the inputs CASE.md lists; mark everything else unavailable.

Write your outputs to ./out/assessment.json and ./out/report.md. In assessment.json set assessor.agent to "claude-code (headless)", assessor.model to "{model}", assessor.skill_version to the skill's metadata version, and assessor.condition to "{condition}".
Validate with `.claude/skills/change-risk/scripts/validate-assessment out/assessment.json --repo repo` and fix every error before you finish. Then render out/report.md with the skill's render-report script.
Do not try to access the network, GitHub, or any path outside this directory."""


def run_one(pr: int, condition: str, model: str, run: int, work: Path, results: Path, budget: float) -> dict:
    case_id = f"stack-{pr}"
    case_dir = work / f"{case_id}-{condition}-r{run}"
    subprocess.run([sys.executable, str(ROOT / "harness" / "prepare_case.py"), "--pr", str(pr),
                    "--condition", condition, "--dest", str(case_dir)], check=True, capture_output=True)
    (case_dir / "out").mkdir()
    prompt = PROMPT.format(model=model, condition=condition)
    claude = [
        "claude", "-p", prompt, "--model", model, "--output-format", "stream-json", "--verbose",
        "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
        "--allowedTools", *ALLOWED_TOOLS, "--disallowedTools", *DISALLOWED_TOOLS,
        "--max-budget-usd", str(budget), "--no-session-persistence",
    ]
    mounts = " && ".join(f"mount -t tmpfs none {shlex.quote(p)}" for p in HIDE if os.path.exists(p))
    inner = f"{mounts} && cd {shlex.quote(str(case_dir))} && exec {shlex.join(claude)}"
    env = {**os.environ, "GIT_ALLOW_PROTOCOL": "file", "GIT_TERMINAL_PROMPT": "0"}
    started = dt.datetime.now(dt.timezone.utc)
    with open(case_dir / "transcript.jsonl", "w") as out, open(case_dir / "stderr.txt", "w") as err:
        proc = subprocess.run(["unshare", "-m", "--propagation", "private", "sh", "-c", inner],
                              stdout=out, stderr=err, env=env, timeout=3600)
    ended = dt.datetime.now(dt.timezone.utc)

    meta = {"case": case_id, "pr": pr, "condition": condition, "run": run, "model_requested": model,
            "exit_code": proc.returncode, "started": started.isoformat(), "wall_seconds": (ended - started).total_seconds(),
            "isolation": {"hidden_paths": HIDE, "git_protocols": "file", "mcp": "none"}}
    tool_calls: list[dict] = []
    for line in (case_dir / "transcript.jsonl").read_text().splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "result":
            for k in ("total_cost_usd", "duration_ms", "duration_api_ms", "num_turns", "is_error", "subtype", "usage", "modelUsage"):
                meta[k] = ev.get(k)
        if ev.get("type") == "system" and ev.get("subtype") == "init":
            meta["claude_code_version"] = ev.get("claude_code_version")
            meta["model_reported"] = ev.get("model")
            meta["skills_loaded"] = ev.get("skills")
        if ev.get("type") == "assistant":
            for block in ev.get("message", {}).get("content", []):
                if block.get("type") == "tool_use":
                    tool_calls.append({"name": block["name"], "input": block.get("input", {})})
    meta["tool_calls"] = len(tool_calls)
    meta["tool_counts"] = {}
    for t in tool_calls:
        meta["tool_counts"][t["name"]] = meta["tool_counts"].get(t["name"], 0) + 1
    meta["skill_invoked"] = any(t["name"] == "Skill" for t in tool_calls) or any(
        "SKILL.md" in json.dumps(t["input"]) for t in tool_calls)
    meta["audit"] = audit(tool_calls)

    dest = results / condition / f"{case_id}-r{run}"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    for name in ("assessment.json", "report.md"):
        if (case_dir / "out" / name).exists():
            shutil.copy(case_dir / "out" / name, dest / name)
    shutil.copy(case_dir / "transcript.jsonl", dest / "transcript.jsonl")
    if (dest / "assessment.json").exists():
        v = subprocess.run([sys.executable, str(ROOT / ".agents/skills/change-risk/scripts/validate_assessment.py"),
                            str(dest / "assessment.json"), "--repo", str(case_dir / "repo"), "--json"],
                           capture_output=True, text=True)
        meta["validation"] = json.loads(v.stdout) if v.stdout.strip().startswith("{") else {"valid": False, "errors": [v.stdout + v.stderr]}
    else:
        meta["validation"] = {"valid": False, "errors": ["no assessment.json produced"]}
    (dest / "run.json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


NET = re.compile(r"(https?://|curl|wget|urllib|requests\.|socket|api\.github|gh )")


def audit(tool_calls: list[dict]) -> dict:
    findings = []
    for t in tool_calls:
        inp = t["input"]
        if t["name"] in ("Write", "Edit"):  # content is the evaluator's own prose; only the target path matters
            inp = {"file_path": inp.get("file_path")}
        s = json.dumps(inp)
        if NET.search(s):
            findings.append({"tool": t["name"], "why": "network-looking", "input": s[:300]})
        # the evaluator's own scratchpad and its own session directory (the CLI spills long tool output there)
        outside = re.sub(r"(/tmp/claude-0|/root/\.claude/projects)/-srv-cr-[^/\"]*", "", s)
        if re.search(r"/home/claude|/tmp/claude|\.claude/projects|origin/|--all\b|reflog", outside):
            findings.append({"tool": t["name"], "why": "path or history outside the case", "input": s[:300]})
    return {"flags": findings, "clean": not findings}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pr", type=int, action="append", required=True)
    ap.add_argument("--condition", choices="ABC", default="C")
    ap.add_argument("--model", default="claude-opus-5-5")
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--budget", type=float, default=15.0, help="max USD per run")
    ap.add_argument("--work", default="/srv/cr")
    ap.add_argument("--results", default=str(ROOT / "eval" / "change-risk" / "results"))
    args = ap.parse_args()
    work, results = Path(args.work), Path(args.results)
    work.mkdir(parents=True, exist_ok=True)
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(run_one, pr, args.condition, args.model, args.run, work, results, args.budget): pr for pr in args.pr}
        for f in cf.as_completed(futs):
            pr = futs[f]
            try:
                m = f.result()
                print(json.dumps({k: m.get(k) for k in ("case", "condition", "exit_code", "total_cost_usd", "wall_seconds",
                                                         "num_turns", "tool_calls", "skill_invoked")} | {
                    "valid": m["validation"].get("valid"), "audit_clean": m["audit"]["clean"]}), flush=True)
            except Exception as e:  # keep going; a failed run is a recorded result
                print(json.dumps({"case": f"stack-{pr}", "error": repr(e)}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
