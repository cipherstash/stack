#!/usr/bin/env python3
"""Deterministic change evidence for a base..head comparison.

Collects facts from git and the repository tree. It makes no judgement about
risk: every signal is a measurement with a stated meaning and limitation, and
the agent decides what, if anything, it implies.

History-derived signals (churn, co-change, familiarity) read ONLY commits that
are ancestors of BASE. Commits made after the base, including the PR's own
commits and anything merged later, cannot leak into them.

Standard library only. Python 3.9+.

    collect_evidence.py --repo . --base <sha> --head <sha> [--out evidence.json]
                        [--rules rules.json] [--ci ci.json] [--format json|md]
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import re
import subprocess
import sys
from pathlib import PurePosixPath

TOOL = "change-risk/collect-evidence"
VERSION = "1.0.0"

# Path classes. Generic defaults; a repository can extend them with --rules.
# A path may match several classes. Patterns are Python regexes on the
# repository-relative POSIX path.
DEFAULT_RULES: dict[str, list[str]] = {
    "test": [
        r"(^|/)(__tests__|tests?|spec|e2e|integration-tests)/",
        r"\.(test|spec)\.[cm]?[jt]sx?$",
        r"_test\.go$",
        r"(^|/)test_[^/]+\.py$",
        r"\.test-d\.ts$",
    ],
    "docs": [r"\.(md|mdx|rst|txt|adoc)$", r"(^|/)docs?/"],
    "ci_workflow": [r"^\.github/(workflows|actions)/", r"(^|/)\.gitlab-ci\.yml$", r"(^|/)Jenkinsfile$"],
    "release_tooling": [
        r"(^|/)release[^/]*\.(ya?ml|toml|mjs|js|ts|sh)$",
        r"^\.changeset/config\.json$",
        r"(^|/)scripts/.*(release|publish|version|lockstep)[^/]*$",
    ],
    "dependency_manifest": [
        r"(^|/)package\.json$",
        r"(^|/)Cargo\.toml$",
        r"(^|/)go\.mod$",
        r"(^|/)pyproject\.toml$",
        r"(^|/)requirements[^/]*\.txt$",
        r"(^|/)pnpm-workspace\.yaml$",
    ],
    "lockfile": [
        r"(^|/)(pnpm-lock\.yaml|package-lock\.json|yarn\.lock|Cargo\.lock|go\.sum|poetry\.lock|uv\.lock)$",
    ],
    "database_schema": [r"\.sql$", r"(^|/)migrations?/", r"(^|/)schema\.prisma$", r"(^|/)drizzle/"],
    "build_config": [
        r"(^|/)(tsconfig[^/]*\.json|tsup\.config\.[cm]?[jt]s|vite\.config\.[cm]?[jt]s|turbo\.json|biome\.json)$",
        r"(^|/)(Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|mise[^/]*\.toml|Makefile)$",
        r"(^|/)\.cargo/config\.toml$",
    ],
    "public_api_surface": [
        r"(^|/)src/index\.[cm]?[jt]sx?$",
        r"(^|/)index\.d\.ts$",
        r"\.d\.ts$",
        r"(^|/)src/lib\.rs$",
        r"(^|/)(exports|public|api)/",
    ],
    "security_sensitive": [
        r"(?i)(crypt|cipher|keyset|key[-_]?(store|management|provider)|zerokms|kms|secret|token|credential|auth|oidc|jwt|lock[-_]?context|sign|hmac|tenant|permission|acl|polic(y|ies))",
    ],
    "serialization_or_protocol": [
        r"(?i)(serde|serial|codec|payload|wire|protocol|proto|schema|format|envelope|encoding)",
        r"\.proto$",
    ],
    "generated": [r"(?i)(^|/)(generated|gen)/", r"_gen\.go$", r"_stash\.go$", r"\.snap$"],
    "agent_instructions": [r"(^|/)(AGENTS|CLAUDE)\.md$", r"(^|/)SKILL\.md$", r"(^|/)\.claude/"],
}

MANIFEST_NAMES = ("package.json", "Cargo.toml", "go.mod", "pyproject.toml")
LANG_BY_EXT = {
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".rs": "Rust", ".go": "Go", ".py": "Python", ".sql": "SQL", ".sh": "Shell",
    ".yml": "YAML", ".yaml": "YAML", ".toml": "TOML", ".json": "JSON", ".md": "Markdown",
}


class GitError(RuntimeError):
    pass


def git(repo: str, *args: str, check: bool = True) -> str:
    res = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if check and res.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {res.stderr.strip()}")
    return res.stdout


# ---------------------------------------------------------------------------
# change facts


def diff_files(repo: str, base: str, head: str) -> list[dict]:
    status: dict[str, tuple[str, str | None]] = {}
    for line in git(repo, "diff", "--name-status", "-M", base, head).splitlines():
        parts = line.split("\t")
        code = parts[0]
        if code.startswith("R") or code.startswith("C"):
            status[parts[2]] = (code[0], parts[1])
        else:
            status[parts[1]] = (code[0], None)
    files = []
    for line in git(repo, "diff", "--numstat", "-M", base, head).splitlines():
        a, d, path = line.split("\t", 2)
        if " => " in path:
            path = re.sub(r"\{([^{}]*) => ([^{}]*)\}", r"\2", path)
            if " => " in path:
                path = path.split(" => ", 1)[1]
            path = re.sub(r"/+", "/", path)
        st, old = status.get(path, ("M", None))
        files.append(
            {
                "path": path,
                "status": {"A": "added", "D": "deleted", "R": "renamed", "C": "copied"}.get(st, "modified"),
                "previous_path": old,
                "additions": None if a == "-" else int(a),
                "deletions": None if d == "-" else int(d),
                "binary": a == "-",
            }
        )
    return files


def compile_rules(extra: dict[str, list[str]] | None) -> dict[str, list[re.Pattern]]:
    rules = {k: list(v) for k, v in DEFAULT_RULES.items()}
    for k, v in (extra or {}).items():
        rules.setdefault(k, []).extend(v)
    return {k: [re.compile(p) for p in v] for k, v in rules.items()}


def classify(path: str, rules: dict[str, list[re.Pattern]]) -> list[str]:
    return sorted(k for k, pats in rules.items() if any(p.search(path) for p in pats))


def tracked_manifest_dirs(repo: str, rev: str) -> list[str]:
    dirs = set()
    for p in git(repo, "ls-tree", "-r", "--name-only", rev).splitlines():
        name = PurePosixPath(p).name
        if name in MANIFEST_NAMES and "node_modules/" not in p:
            dirs.add(str(PurePosixPath(p).parent))
    return sorted(dirs, key=lambda d: (-d.count("/"), d))


def component_of(path: str, manifest_dirs: list[str]) -> str:
    """Nearest ancestor directory that holds a package manifest; '.' is the root."""
    for d in manifest_dirs:  # deepest first
        if d == ".":
            continue
        if path == d or path.startswith(d + "/"):
            return d
    return "."


# ---------------------------------------------------------------------------
# history (ancestors of base only)


def history(repo: str, base: str, max_commits: int) -> list[dict]:
    raw = git(
        repo,
        "log",
        "--no-merges",
        "--no-renames",
        f"--max-count={max_commits}",
        "--format=%x1e%H%x1f%cI%x1f%aE",
        "--name-only",
        base,
    )
    commits = []
    for rec in raw.split("\x1e"):
        if not rec.strip():
            continue
        head, _, rest = rec.partition("\n")
        sha, date, email = head.split("\x1f")
        files = [f for f in rest.splitlines() if f.strip()]
        commits.append({"sha": sha, "date": date, "author": email.lower(), "files": files})
    return commits


def churn(commits: list[dict], paths: list[str], base_date: dt.datetime, recent_days: int) -> dict:
    wanted = set(paths)
    total = collections.Counter()
    recent = collections.Counter()
    authors: dict[str, set] = collections.defaultdict(set)
    cutoff = base_date - dt.timedelta(days=recent_days)
    for c in commits:
        cdate = dt.datetime.fromisoformat(c["date"])
        for f in c["files"]:
            if f in wanted:
                total[f] += 1
                authors[f].add(c["author"])
                if cdate >= cutoff:
                    recent[f] += 1
    return {
        p: {"commits": total[p], f"commits_last_{recent_days}d": recent[p], "distinct_authors": len(authors[p])}
        for p in paths
    }


def co_change(
    commits: list[dict],
    changed: list[str],
    min_support: int,
    min_confidence: float,
    max_files_per_commit: int,
    head_paths: set[str],
) -> dict:
    """Files that historically changed with a changed file but are absent from this diff.

    confidence(A->B) = commits touching A and B / commits touching A.
    Commits touching more than max_files_per_commit files are ignored: bulk
    renames, imports and formatting sweeps couple everything to everything.
    """
    changed_set = set(changed)
    touches = collections.Counter()
    pair = collections.Counter()
    skipped = 0
    for c in commits:
        files = set(c["files"])
        if len(files) > max_files_per_commit:
            skipped += 1
            continue
        hit = files & changed_set
        if not hit:
            continue
        for a in hit:
            touches[a] += 1
            for b in files - {a}:
                pair[(a, b)] += 1
    missing = []
    for (a, b), n in pair.items():
        if b in changed_set or n < min_support:
            continue
        conf = n / touches[a]
        if conf >= min_confidence:
            missing.append(
                {
                    "changed_file": a,
                    "usually_changes_with": b,
                    "co_commits": n,
                    "confidence": round(conf, 2),
                    "exists_at_head": b in head_paths,
                }
            )
    missing.sort(key=lambda x: (-x["confidence"], -x["co_commits"], x["changed_file"], x["usually_changes_with"]))
    return {"omitted_co_changes": missing[:40], "bulk_commits_ignored": skipped}


# ---------------------------------------------------------------------------
# ownership


def codeowners(repo: str, rev: str) -> list[tuple[str, list[str]]]:
    for loc in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        text = git(repo, "show", f"{rev}:{loc}", check=False)
        if text:
            rules = []
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                pat, *owners = line.split()
                rules.append((pat, owners))
            return rules
    return []


def _codeowners_regex(pat: str) -> re.Pattern:
    anchored = pat.startswith("/") or "/" in pat.rstrip("/")
    p = pat.strip("/") if pat != "/" else ""
    directory = pat.endswith("/")
    out = ""
    i = 0
    while i < len(p):
        if p.startswith("**", i):
            out += ".*"
            i += 2
        elif p[i] == "*":
            out += "[^/]*"
            i += 1
        elif p[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(p[i])
            i += 1
    prefix = "^" if anchored else "^(?:.*/)?"
    suffix = "/.*$" if directory else "(?:/.*)?$"
    return re.compile(prefix + out + suffix)


def owners_for(path: str, rules: list[tuple[str, list[str]]]) -> list[str]:
    match: list[str] = []
    for pat, owners in rules:  # last match wins, as on GitHub
        if pat == "*" or _codeowners_regex(pat).match(path):
            match = owners
    return match


# ---------------------------------------------------------------------------
# dependencies


def _json_at(repo: str, rev: str, path: str) -> dict | None:
    text = git(repo, "show", f"{rev}:{path}", check=False)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def package_json_changes(repo: str, base: str, head: str, path: str) -> dict:
    old = _json_at(repo, base, path) or {}
    new = _json_at(repo, head, path) or {}
    out: dict = {"file": path, "dependencies": []}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        o, n = old.get(section, {}) or {}, new.get(section, {}) or {}
        for name in sorted(set(o) | set(n)):
            if o.get(name) != n.get(name):
                out["dependencies"].append({"section": section, "name": name, "from": o.get(name), "to": n.get(name)})
    for key in ("exports", "main", "module", "types", "bin", "engines", "version", "type", "files"):
        if old.get(key) != new.get(key):
            out.setdefault("fields_changed", []).append(key)
    return out


TOML_DEP = re.compile(r'^\s*([A-Za-z0-9_\-]+)\s*=\s*(.+)$')


def cargo_toml_changes(repo: str, base: str, head: str, path: str) -> dict:
    def deps(rev: str) -> dict[str, str]:
        text = git(repo, "show", f"{rev}:{path}", check=False)
        section, out = "", {}
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("["):
                section = s.strip("[]")
                continue
            if "dependencies" in section:
                m = TOML_DEP.match(line)
                if m:
                    out[f"{section}:{m.group(1)}"] = m.group(2).strip()
        return out

    o, n = deps(base), deps(head)
    changes = [
        {"section": k.split(":")[0], "name": k.split(":")[1], "from": o.get(k), "to": n.get(k)}
        for k in sorted(set(o) | set(n))
        if o.get(k) != n.get(k)
    ]
    return {"file": path, "dependencies": changes}


def dependency_changes(repo: str, base: str, head: str, files: list[dict]) -> list[dict]:
    out = []
    for f in files:
        name = PurePosixPath(f["path"]).name
        if f["status"] == "deleted":
            continue
        if name == "package.json":
            c = package_json_changes(repo, base, head, f["path"])
        elif name == "Cargo.toml":
            c = cargo_toml_changes(repo, base, head, f["path"])
        else:
            continue
        if c.get("dependencies") or c.get("fields_changed"):
            out.append(c)
    return out


# ---------------------------------------------------------------------------
# tests


def related_tests(path: str, head_paths: list[str], test_re: list[re.Pattern], repo: str = "", head: str = "", component: str = ".") -> tuple[list[str], str]:
    stem = PurePosixPath(path).name
    for ext in (".d.ts", ".tsx", ".ts", ".mts", ".cts", ".mjs", ".cjs", ".js", ".rs", ".go", ".py"):
        if stem.endswith(ext):
            stem = stem[: -len(ext)]
            break
    if len(stem) < 3 or stem in ("index", "mod", "lib", "main", "types", "utils"):
        # too generic to match by name; directory-level heuristics follow
        stem = None
    comp_dir = str(PurePosixPath(path).parent)
    hits = []
    for t in head_paths:
        if not any(p.search(t) for p in test_re):
            continue
        tname = PurePosixPath(t).name
        if stem and (tname.startswith(stem + ".") or tname.startswith(stem + "_") or tname == f"test_{stem}.py"):
            hits.append(t)
    if hits:
        return sorted(hits)[:8], "name"
    if path.endswith(".go"):
        hits = [t for t in head_paths if t.startswith(comp_dir + "/") and t.endswith("_test.go") and t.count("/") == path.count("/")]
        if hits:
            return sorted(hits)[:8], "package"
    if stem and repo:
        # a test in the same component that names the module, e.g. in an import path
        scope = [] if component == "." else ["--", component]
        needles = ["-e", f"/{stem}"]
        if re.search(r"[-_]", stem):  # bulk-encrypt -> bulkEncrypt, the exported name
            needles += ["-e", re.sub(r"[-_]([a-z0-9])", lambda m: m.group(1).upper(), stem)]
        out = git(repo, "grep", "-l", "-F", *needles, head, *scope, check=False)
        refs = [ln.split(":", 1)[1] for ln in out.splitlines() if ":" in ln]
        hits = [t for t in refs if any(p.search(t) for p in test_re)]
        if hits:
            return sorted(hits)[:8], "reference"
    return [], "none"


# ---------------------------------------------------------------------------


def collect(args) -> dict:
    repo = args.repo
    base = git(repo, "rev-parse", "--verify", f"{args.base}^{{commit}}").strip()
    head = git(repo, "rev-parse", "--verify", f"{args.head}^{{commit}}").strip()
    merge_base = git(repo, "merge-base", base, head, check=False).strip() or None
    base_date = dt.datetime.fromisoformat(git(repo, "show", "-s", "--format=%cI", base).strip())
    rules = compile_rules(json.load(open(args.rules)) if args.rules else None)

    files = diff_files(repo, base, head)
    paths = [f["path"] for f in files]
    head_paths_list = git(repo, "ls-tree", "-r", "--name-only", head).splitlines()
    head_paths = set(head_paths_list)
    manifest_dirs = tracked_manifest_dirs(repo, head)
    co_rules = codeowners(repo, base)

    for f in files:
        f["classes"] = classify(f["path"], rules)
        f["component"] = component_of(f["path"], manifest_dirs)
        f["language"] = LANG_BY_EXT.get(PurePosixPath(f["path"]).suffix, "other")

    comps = collections.Counter(f["component"] for f in files)
    classes = collections.Counter(c for f in files for c in f["classes"])
    top_dirs = collections.Counter(f["path"].split("/", 1)[0] if "/" in f["path"] else "." for f in files)

    commits = history(repo, base, args.max_history)
    ch = churn(commits, paths, base_date, args.recent_days)
    hot = sorted(
        ({"path": p, **v} for p, v in ch.items() if v["commits"]),
        key=lambda x: (-x["commits"], x["path"]),
    )[:15]
    cc = co_change(commits, paths, args.min_support, args.min_confidence, args.max_files_per_commit, head_paths)

    pr_authors = sorted(
        {a.lower() for a in git(repo, "log", "--format=%aE", f"{base}..{head}").split() if a}
    )
    familiarity = {}
    for a in pr_authors:
        prior = sum(1 for c in commits if c["author"] == a and set(c["files"]) & set(paths))
        familiarity[a] = {"prior_commits_touching_changed_files": prior}

    src_files = [f for f in files if "test" not in f["classes"] and "docs" not in f["classes"]
                 and f["language"] in ("TypeScript", "JavaScript", "Rust", "Go", "Python") and f["status"] != "deleted"]
    test_re = rules["test"]
    test_map = []
    for f in src_files:
        rel, how = related_tests(f["path"], head_paths_list, test_re, repo, head, f["component"])
        test_map.append({"source": f["path"], "related_tests_at_head": rel, "match": how,
                         "related_test_changed": any(r in set(paths) for r in rel)})

    ci = None
    if args.ci:
        ci = json.load(open(args.ci))

    adds = sum(f["additions"] or 0 for f in files)
    dels = sum(f["deletions"] or 0 for f in files)
    return {
        "tool": {"name": TOOL, "version": VERSION},
        "repository": args.repository or os.path.basename(os.path.abspath(repo)),
        "base_sha": base,
        "head_sha": head,
        "merge_base_sha": merge_base,
        "base_is_merge_base": merge_base == base,
        "history_scope": {
            "rule": "ancestors of base_sha only; no commit after the base is read",
            "cutoff_commit": base,
            "cutoff_date": base_date.isoformat(),
            "commits_read": len(commits),
            "max_commits": args.max_history,
            "merges_excluded": True,
        },
        "change_size": {
            "files": len(files),
            "additions": adds,
            "deletions": dels,
            "binary_files": sum(1 for f in files if f["binary"]),
            "by_status": dict(collections.Counter(f["status"] for f in files)),
        },
        "dispersion": {
            "components": dict(comps.most_common()),
            "component_count": len(comps),
            "top_level_dirs": dict(top_dirs.most_common()),
            "languages": dict(collections.Counter(f["language"] for f in files).most_common()),
        },
        "path_classes": dict(classes.most_common()),
        "files": files,
        "churn": {"recent_window_days": args.recent_days, "hotspots": hot},
        "co_change": {
            "min_support": args.min_support,
            "min_confidence": args.min_confidence,
            "max_files_per_commit": args.max_files_per_commit,
            **cc,
        },
        "ownership": {
            "codeowners_found": bool(co_rules),
            "owners_by_file": {p: owners_for(p, co_rules) for p in paths} if co_rules else {},
            "pr_commit_authors": len(pr_authors),
            "author_familiarity": {f"author_{i + 1}": v for i, (_, v) in enumerate(sorted(familiarity.items()))},
        },
        "dependencies": dependency_changes(repo, base, head, files),
        "tests": {
            "test_files_changed": sum(1 for f in files if "test" in f["classes"]),
            "source_files_changed": len(src_files),
            "source_without_related_test": [t["source"] for t in test_map if not t["related_tests_at_head"]],
            "source_with_related_test_unchanged": [t["source"] for t in test_map if t["related_tests_at_head"] and not t["related_test_changed"]],
            "mapping": test_map,
            "note": "Mapping by file name, Go package, or a test in the same component naming the module path. A related test existing or changing says nothing about whether it ran or passed.",
        },
        "ci": ci if ci is not None else {"available": False, "note": "No CI results supplied (--ci). Do not infer that checks passed."},
        "signal_meanings": SIGNAL_MEANINGS,
    }


SIGNAL_MEANINGS = {
    "change_size": "Lines and files changed. Large diffs are harder to review; size alone does not indicate impact.",
    "dispersion": "Components = nearest directory with a package manifest. Several components means the change crosses package boundaries.",
    "path_classes": "Regex classification of paths. A class is a prompt to look, not evidence of a contract change.",
    "churn": "Commit counts per changed file over base ancestry. High churn marks a frequently-modified area; it is not a defect predictor on its own.",
    "co_change": "Files that historically changed together with a changed file but are absent here. Can indicate an incomplete change, or nothing.",
    "ownership": "CODEOWNERS at base and how often the PR's authors previously committed to these files. Contextual only; not a judgement of the author.",
    "dependencies": "Manifest entries whose version spec changed. Lockfile-only resolution changes appear in files, not here.",
    "tests": "Name-based mapping from source files to test files. Existence of a test is not evidence it covers the change or that it passed.",
}


def to_markdown(ev: dict) -> str:
    cs, dp = ev["change_size"], ev["dispersion"]
    lines = [
        f"# Change evidence: {ev['repository']} {ev['base_sha'][:10]}..{ev['head_sha'][:10]}",
        "",
        f"- History cutoff: {ev['history_scope']['cutoff_date']} (base ancestry only, {ev['history_scope']['commits_read']} commits read)",
        f"- Size: {cs['files']} files, +{cs['additions']}/-{cs['deletions']}, by status {cs['by_status']}",
        f"- Components ({dp['component_count']}): " + ", ".join(f"{k} ({v})" for k, v in dp["components"].items()),
        f"- Path classes: " + ", ".join(f"{k} ({v})" for k, v in ev["path_classes"].items()),
        f"- Tests: {ev['tests']['test_files_changed']} test files changed for {ev['tests']['source_files_changed']} source files; "
        f"{len(ev['tests']['source_without_related_test'])} source files have no name-matched test",
        "",
        "## Hotspots (commits before base)",
    ]
    for h in ev["churn"]["hotspots"][:10]:
        lines.append(f"- `{h['path']}`: {h['commits']} commits, {h[next(k for k in h if k.startswith('commits_last'))]} recent, {h['distinct_authors']} authors")
    lines += ["", "## Usually co-changed, absent here"]
    for c in ev["co_change"]["omitted_co_changes"][:12]:
        lines.append(f"- `{c['changed_file']}` → `{c['usually_changes_with']}` ({c['co_commits']} commits, conf {c['confidence']})")
    if ev["dependencies"]:
        lines += ["", "## Dependency changes"]
        for d in ev["dependencies"]:
            for x in d.get("dependencies", [])[:20]:
                lines.append(f"- `{d['file']}` {x['section']} {x['name']}: {x['from']} → {x['to']}")
            if d.get("fields_changed"):
                lines.append(f"- `{d['file']}` fields changed: {', '.join(d['fields_changed'])}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".")
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--repository", help="owner/name label for the output")
    ap.add_argument("--rules", help="JSON object of extra path-class regexes")
    ap.add_argument("--ci", help="JSON file of CI results for head (optional)")
    ap.add_argument("--max-history", type=int, default=5000)
    ap.add_argument("--recent-days", type=int, default=90)
    ap.add_argument("--min-support", type=int, default=3)
    ap.add_argument("--min-confidence", type=float, default=0.5)
    ap.add_argument("--max-files-per-commit", type=int, default=40)
    ap.add_argument("--format", choices=("json", "md"), default="json")
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    try:
        ev = collect(args)
    except GitError as e:
        print(f"collect-evidence: {e}", file=sys.stderr)
        return 2
    text = json.dumps(ev, indent=2) + "\n" if args.format == "json" else to_markdown(ev)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
