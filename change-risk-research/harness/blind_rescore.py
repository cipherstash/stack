#!/usr/bin/env python3
"""Re-label every holdout finding blind, with a second, independent adjudicator.

    blind_rescore.py prepare            build packets and the (hidden) id maps
    blind_rescore.py run [--jobs 3]     run the adjudicator on every packet
    blind_rescore.py collect            write eval/adjudication-blind/<evaluator>/<case>.json

The second adjudicator is a fresh headless Claude Code session per case. It sees:
  - the PR title, the review-time diff and a checkout of the head (head ancestry only);
  - the case's known defects (description, mechanism, match criteria), which it needs to decide `match`;
  - every finding from change-risk A, B and C (run 1) and CodeRabbit, pooled, shuffled and renumbered
    F-01, F-02, ... with no evaluator name, no finding id, no `basis` or impact, and no nitpick flag;
  - the label rules from research/methodology.md section 5, verbatim.
It does not see the first adjudicator's labels, the expert impact ratings, the evaluator identities,
this research directory, the evaluator transcripts or any later history. Isolation is the same as for
the evaluators (run_evaluation.py): private mount namespace, hidden paths, git file protocol, no MCP,
no web tools. The map from F-nn back to (evaluator, finding id) stays in this directory, which is hidden.
Writing style still differs between the skill and CodeRabbit, so evaluator blinding is partial.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import random
import shlex
import shutil
import subprocess
from pathlib import Path

from run_evaluation import NET, ROOT

HIDE = ["/home/claude/stack", "/tmp/claude-0", "/root/.claude/projects", "/srv/cr"]
WORK = Path("/srv/blind")
MAPS = ROOT / "eval/adjudication-blind/maps"
RAW = ROOT / "eval/adjudication-blind/raw"
OUT = ROOT / "eval/adjudication-blind"
EVALUATORS = ["change-risk/A", "change-risk/B", "change-risk/C", "coderabbit/original"]
MODEL = "claude-opus-5-5"

ALLOWED_TOOLS = [
    "Read", "Grep", "Glob", "Write", "Edit",
    "Bash(git:*)", "Bash(grep:*)", "Bash(rg:*)", "Bash(sed:*)", "Bash(awk:*)", "Bash(ls:*)", "Bash(cat:*)",
    "Bash(head:*)", "Bash(tail:*)", "Bash(wc:*)", "Bash(find:*)", "Bash(jq:*)", "Bash(python3:*)",
    "Bash(cd:*)",
]
DISALLOWED_TOOLS = ["WebFetch", "WebSearch", "Agent", "Task", "NotebookEdit", "Skill"]

LABEL_RULES = """| Label | Rule |
|---|---|
| `match` | Same mechanism and same consequence class as a known defect, per that defect's `match_criteria`. Naming the subsystem or file of a known defect is **not** a match. |
| `valid` | Not a known defect, but technically plausible, caused by this change, and supported by the code it cites (cited lines spot-checked). |
| `unsupported` | The mechanism is not supported by the cited code, or the finding is not shown to be caused by this change. |
| `incorrect` | Factually wrong about what the code does, or describes a pre-existing condition as caused by the change. |
| `trivial` | True but immaterial to release risk (style, naming, comment wording). |

Also per finding: `evidence_ok` (do the cited locations exist and show what is claimed; true, false, or null if not checked) and `actionable` (for match/valid only: does it propose or imply a verification or mitigation a maintainer could do; null otherwise)."""

PROMPT = """You are adjudicating findings that automated reviewers reported on one pull request. Work only from this directory.

- PACKET.md: the PR title, the known defects later found in this change, and the findings to label.
- changes.diff: the review-time diff (base...head).
- repo/: a git checkout of the head. Use `git -C repo ...`; base and head shas are in PACKET.md.

Label every finding in PACKET.md with exactly one label, using these rules:

{rules}

Read the code a finding cites before you label it `valid`, `unsupported` or `incorrect`. A finding can match more than one known defect. Several findings may describe the same issue; label each one on its own merits. Judge findings against the head of this PR, not against later history.

Write ./labels.json, and nothing else, in this shape:
{{"labels": [{{"id": "F-01", "label": "valid", "matches": [], "evidence_ok": true, "actionable": true, "reason": "one sentence"}}, ...]}}
Every finding id must appear exactly once. Do not try to access the network, GitHub, or any path outside this directory."""


def finding_text_skill(f: dict, evidence: dict) -> str:
    parts = [f"**{f.get('title', '').strip()}**"]
    for k in ("trigger", "mechanism", "consequence", "missing_verification", "mitigation"):
        if f.get(k):
            v = f[k] if isinstance(f[k], str) else "; ".join(map(str, f[k]))
            parts.append(f"- {k}: {v}")
    for eid in f.get("evidence", []):
        e = evidence.get(eid)
        if e and e.get("path"):
            loc = f"{e['path']}:{e.get('line_start', '')}-{e.get('line_end', '')} ({e.get('rev', 'head')})"
            parts.append(f"- cited: {loc}: {e.get('claim', '')}")
        elif e:
            parts.append(f"- cited ({e.get('kind', '')}): {e.get('claim', '')}")
    return "\n".join(parts)


def finding_text_cr(f: dict) -> str:
    loc = f"{f['path']}:{f['line']}" if f.get("path") else "(no location)"
    return f"**{f['claim'].strip()}**\n- cited: {loc}"


def prepare() -> None:
    corpus = [c for c in json.loads((ROOT / "eval/corpus.json").read_text())["cases"] if c["split"] == "holdout"]
    MAPS.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    for case in corpus:
        cid, pr = case["id"], case["pr"]
        pooled: list[tuple[str, str, str]] = []  # (evaluator, finding id, text)
        for ev in EVALUATORS:
            adj = ROOT / "eval/adjudication" / ev / f"{cid}.json"
            if not adj.exists():
                continue
            ids = [f["id"] for f in json.loads(adj.read_text())["findings"]]
            if ev.startswith("change-risk/"):
                cond = ev.split("/")[1]
                a = json.loads((ROOT / f"eval/change-risk/results/{cond}/{cid}-r1/assessment.json").read_text())
                evidence = {e["id"]: e for e in a.get("evidence", [])}
                by_id = {f["id"]: finding_text_skill(f, evidence) for f in a["failure_scenarios"]}
            else:
                cr = json.loads((ROOT / f"eval/coderabbit/{pr}.json").read_text())
                by_id = {f["id"]: finding_text_cr(f) for f in cr["findings"]}
            pooled += [(ev, i, by_id[i]) for i in ids]
        random.Random(f"blind-{cid}").shuffle(pooled)
        mapping = {f"F-{n:02d}": {"evaluator": ev, "finding": i} for n, (ev, i, _) in enumerate(pooled, 1)}
        (MAPS / f"{cid}.json").write_text(json.dumps(mapping, indent=2) + "\n")

        gt = json.loads((ROOT / f"eval/ground-truth/{pr}.json").read_text())
        kds = [k for k in gt.get("known_defects", []) if not k.get("added_post_hoc")]
        src = Path(f"/srv/cr/{cid}-C-r1")
        dest = WORK / cid
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir()
        subprocess.run(["git", "clone", "-q", "--no-local", str(src / "repo"), str(dest / "repo")], check=True)
        shutil.copy(src / "changes.diff", dest / "changes.diff")
        lines = [f"# {cid}: {case.get('title', '')}", "",
                 f"Base: `{case['base_sha']}`  Head: `{case['head_sha']}`", "", "## Known defects", ""]
        if kds:
            for k in kds:
                lines += [f"### {k['id']}", "", f"- description: {k['description']}",
                          f"- mechanism: {k.get('mechanism', '')}", f"- match_criteria: {k.get('match_criteria', '')}", ""]
        else:
            lines += ["None known. No finding can be `match`.", ""]
        lines += ["## Findings to label", ""]
        for fid, (_, _, text) in zip(mapping, pooled):
            lines += [f"### {fid}", "", text, ""]
        (dest / "PACKET.md").write_text("\n".join(lines))
    print(f"prepared {len(corpus)} packets in {WORK}")


def run_one(cid: str) -> dict:
    d = WORK / cid
    claude = ["claude", "-p", PROMPT.format(rules=LABEL_RULES), "--model", MODEL, "--output-format", "stream-json",
              "--verbose", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
              "--allowedTools", *ALLOWED_TOOLS, "--disallowedTools", *DISALLOWED_TOOLS,
              "--max-budget-usd", "8", "--no-session-persistence"]
    mounts = " && ".join(f"mount -t tmpfs none {shlex.quote(p)}" for p in HIDE if os.path.exists(p))
    inner = f"{mounts} && cd {shlex.quote(str(d))} && exec {shlex.join(claude)}"
    env = {**os.environ, "GIT_ALLOW_PROTOCOL": "file", "GIT_TERMINAL_PROMPT": "0"}
    started = dt.datetime.now(dt.timezone.utc)
    with open(d / "transcript.jsonl", "w") as out, open(d / "stderr.txt", "w") as err:
        proc = subprocess.run(["unshare", "-m", "--propagation", "private", "sh", "-c", inner],
                              stdout=out, stderr=err, env=env, timeout=3600)
    meta = {"case": cid, "exit_code": proc.returncode, "started": started.isoformat(),
            "wall_seconds": (dt.datetime.now(dt.timezone.utc) - started).total_seconds(), "net_flags": []}
    for line in (d / "transcript.jsonl").read_text().splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "result":
            meta["total_cost_usd"] = ev.get("total_cost_usd")
        if ev.get("type") == "system" and ev.get("subtype") == "init":
            meta["claude_code_version"] = ev.get("claude_code_version")
            meta["model_reported"] = ev.get("model")
        if ev.get("type") == "assistant":
            for b in ev.get("message", {}).get("content", []):
                if b.get("type") == "tool_use" and b["name"] == "Bash" and NET.search(b["input"].get("command", "")):
                    meta["net_flags"].append(b["input"]["command"][:200])
    RAW.mkdir(parents=True, exist_ok=True)
    if (d / "labels.json").exists():
        shutil.copy(d / "labels.json", RAW / f"{cid}.labels.json")
    (RAW / f"{cid}.run.json").write_text(json.dumps(meta, indent=2) + "\n")
    subprocess.run(["gzip", "-c", str(d / "transcript.jsonl")], stdout=open(RAW / f"{cid}.transcript.jsonl.gz", "wb"))
    return meta


def run(jobs: int, only: list[str]) -> None:
    cases = only or sorted(p.name for p in WORK.iterdir() if p.is_dir())
    with cf.ThreadPoolExecutor(jobs) as ex:
        for m in ex.map(run_one, cases):
            print(m["case"], m["exit_code"], m.get("total_cost_usd"), len(m["net_flags"]), flush=True)


def collect() -> None:
    for mp in sorted(MAPS.glob("*.json")):
        cid = mp.stem
        mapping = json.loads(mp.read_text())
        lf = RAW / f"{cid}.labels.json"
        if not lf.exists():
            print("missing", cid)
            continue
        labels = {x["id"]: x for x in json.loads(lf.read_text())["labels"]}
        missing = set(mapping) - set(labels)
        if missing:
            print("incomplete", cid, sorted(missing))
            continue
        for ev in EVALUATORS:
            first = ROOT / "eval/adjudication" / ev / f"{cid}.json"
            if not first.exists():
                continue
            doc = json.loads(first.read_text())
            back = {m["finding"]: labels[fid] for fid, m in mapping.items() if m["evaluator"] == ev}
            for f in doc["findings"]:
                b = back[f["id"]]
                f.update(label=b["label"], matches=b.get("matches", []), evidence_ok=b.get("evidence_ok"),
                         actionable=b.get("actionable"), note=b.get("reason", ""))
            if ev == "coderabbit/original":
                doc["attention"] = any(x["label"] in ("match", "valid") and not x["nitpick"] for x in doc["findings"])
            doc["adjudicator"] = "blind second adjudicator (harness/blind_rescore.py)"
            dest = OUT / ev / f"{cid}.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(doc, indent=2) + "\n")
    print("collected")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["prepare", "run", "collect"])
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--case", action="append", default=[])
    a = ap.parse_args()
    {"prepare": prepare, "collect": collect}.get(a.step, lambda: run(a.jobs, a.case))()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
