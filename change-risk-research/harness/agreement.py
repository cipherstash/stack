#!/usr/bin/env python3
"""Compare the first (non-blind) adjudication with the blind second one.

    agreement.py

Prints per-finding agreement (raw and Cohen's kappa over the five labels and over sound/not sound),
the confusion matrix, known-defect matches that differ, and the headline metrics under each set of
labels. Writes eval/agreement.json.
"""

from __future__ import annotations

import collections
import json

from score_results import ROOT, score

LABELS = ["match", "valid", "unsupported", "incorrect", "trivial"]
EVALUATORS = ["change-risk/C", "change-risk/B", "change-risk/A", "coderabbit/original"]


def kappa(pairs: list[tuple[str, str]], cats: list[str]) -> float | None:
    n = len(pairs)
    if not n:
        return None
    po = sum(a == b for a, b in pairs) / n
    ca = collections.Counter(a for a, _ in pairs)
    cb = collections.Counter(b for _, b in pairs)
    pe = sum(ca[c] * cb[c] for c in cats) / (n * n)
    return round((po - pe) / (1 - pe), 3) if pe < 1 else None


def sound(label: str) -> str:
    return "sound" if label in ("match", "valid") else "not"


def main() -> int:
    corpus = {c["id"]: c for c in json.loads((ROOT / "eval/corpus.json").read_text())["cases"]}
    gt = {int(p.stem): json.loads(p.read_text()) for p in (ROOT / "eval/ground-truth").glob("*.json")}
    first_root, blind_root = ROOT / "eval/adjudication", ROOT / "eval/adjudication-blind"
    out: dict = {"by_evaluator": {}, "disagreements": []}
    all_pairs: list[tuple[str, str]] = []
    confusion = collections.Counter()
    for ev in EVALUATORS:
        pairs = []
        kd_first, kd_blind = set(), set()
        for p in sorted((blind_root / ev).glob("*.json")):
            b = json.loads(p.read_text())
            f = json.loads((first_root / ev / p.name).read_text())
            fb = {x["id"]: x for x in b["findings"]}
            for x in f["findings"]:
                y = fb[x["id"]]
                pairs.append((x["label"], y["label"]))
                confusion[(x["label"], y["label"])] += 1
                kd_first |= {(p.stem, m) for m in x.get("matches") or []}
                kd_blind |= {(p.stem, m) for m in y.get("matches") or []}
                if x["label"] != y["label"]:
                    out["disagreements"].append({"evaluator": ev, "case": p.stem, "finding": x["id"],
                                                 "first": x["label"], "blind": y["label"],
                                                 "title": x["title"][:120], "blind_reason": y.get("note", "")})
        all_pairs += pairs
        out["by_evaluator"][ev] = {
            "findings": len(pairs),
            "raw_agreement": round(sum(a == b for a, b in pairs) / len(pairs), 3) if pairs else None,
            "kappa_5_labels": kappa(pairs, LABELS),
            "kappa_sound": kappa([(sound(a), sound(b)) for a, b in pairs], ["sound", "not"]),
            "known_defects_first": sorted(f"{c}:{k}" for c, k in kd_first),
            "known_defects_blind": sorted(f"{c}:{k}" for c, k in kd_blind),
            "metrics_first": score(first_root / ev, gt, corpus, "holdout"),
            "metrics_blind": score(blind_root / ev, gt, corpus, "holdout"),
        }
    out["overall"] = {"findings": len(all_pairs),
                      "raw_agreement": round(sum(a == b for a, b in all_pairs) / len(all_pairs), 3),
                      "kappa_5_labels": kappa(all_pairs, LABELS),
                      "kappa_sound": kappa([(sound(a), sound(b)) for a, b in all_pairs], ["sound", "not"]),
                      "confusion_first_by_blind": {f"{a}->{b}": n for (a, b), n in sorted(confusion.items())}}
    (ROOT / "eval/agreement.json").write_text(json.dumps(out, indent=2) + "\n")

    o = out["overall"]
    print(f"overall: {o['findings']} findings, raw {o['raw_agreement']}, kappa {o['kappa_5_labels']}, "
          f"kappa sound/not {o['kappa_sound']}")
    print("\nconfusion (rows first, columns blind)")
    print("| first \\ blind | " + " | ".join(LABELS) + " |")
    print("|---" * (len(LABELS) + 1) + "|")
    for a in LABELS:
        print(f"| {a} | " + " | ".join(str(confusion[(a, b)]) for b in LABELS) + " |")

    def pct(m: dict) -> str:
        return f"{m['k']}/{m['n']} ({m['value']:.0%})" if m and m.get("n") else "n/a"

    print("\n| Evaluator | Raw agreement | κ (5 labels) | κ (sound) | Precision first | Precision blind "
          "| Recall first | Recall blind | FP/case first | FP/case blind |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for ev, r in out["by_evaluator"].items():
        a, b = r["metrics_first"], r["metrics_blind"]
        print(f"| {ev} | {r['raw_agreement']} | {r['kappa_5_labels']} | {r['kappa_sound']} "
              f"| {pct(a['scenario_precision_material'])} | {pct(b['scenario_precision_material'])} "
              f"| {pct(a['known_defect_recall'])} | {pct(b['known_defect_recall'])} "
              f"| {a['false_positive_burden_per_case']} | {b['false_positive_burden_per_case']} |")
        only_first = sorted(set(r["known_defects_first"]) - set(r["known_defects_blind"]))
        only_blind = sorted(set(r["known_defects_blind"]) - set(r["known_defects_first"]))
        if only_first or only_blind:
            print(f"    defects only first: {only_first}; only blind: {only_blind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
