"""v0.5 Part C — run the FROZEN, UNMODIFIED Tier2 on the Part B expanded validation set.

Tier2 is frozen (no prompt/rule/logic edits this round). This harness only CALLS the
existing Tier2LLMJudge on the 92 promptfoo-generated single-turn cases and records every
verdict + reason + evidence_basis. It does NOT touch Tier2 itself.

The 4 v0.4 hand-made regression cases are NOT included (task: exclude them to avoid
double-counting). This eval is on the promptfoo set alone.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

os.environ.setdefault("TIER0_FORCE_SKLEARN", "1")
_REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "dataset" / "src"))
sys.path.insert(0, str(_REPO))

from tier2.llm_judge import Tier2LLMJudge, _calibrate
from tier2.llm_client import chat, _extract_json

N_RUNS = int(os.environ.get("V05C_RUNS", "3"))   # 3 runs to surface run-to-run instability honestly
WORKERS = int(os.environ.get("V05C_WORKERS", "10"))
RETRIES = int(os.environ.get("V05_RETRIES", "4"))


def _judge_call(msgs, temperature=0.0):
    last = None
    for _ in range(RETRIES + 1):
        try:
            content, _, meta = chat(msgs, temperature=temperature, with_reasoning=False)
            parsed = _extract_json(content)
            if parsed is None or "risk_category" not in parsed:
                return {"verdict": "suspicious", "confidence": 0.0, "pcc": None,
                        "evidence_basis": "information_gap", "information_gaps": [],
                        "reason": f"parse failed (finish={meta.get('finish_reason')})"}
            v = str(parsed.get("risk_category", "")).strip().lower()
            if v not in ("benign", "malicious"):
                return {"verdict": "suspicious", "confidence": 0.0, "pcc": None,
                        "evidence_basis": "information_gap",
                        "information_gaps": [f"unknown risk_category {v}"],
                        "reason": "unknown verdict"}
            pcc = bool(parsed.get("purpose_capability_consistent", True))
            conf = _calibrate(parsed.get("confidence"), verdict=v, pcc=pcc)
            basis = str(parsed.get("evidence_basis", "") or "").strip().lower()
            if basis not in ("grounded", "information_gap"):
                basis = "grounded"
            gaps = parsed.get("information_gaps", []) or []
            return {"verdict": v, "confidence": conf, "pcc": pcc,
                    "evidence_basis": basis,
                    "information_gaps": [str(g) for g in gaps] if isinstance(gaps, list) else [],
                    "reason": str(parsed.get("reason", "") or "")}
        except Exception as e:
            last = f"{type(e).__name__}: {e}"; time.sleep(0.4)
    return {"verdict": "suspicious", "confidence": 0.0, "pcc": None,
            "evidence_basis": "information_gap", "information_gaps": [f"call failed: {last}"],
            "reason": "call failed"}


def main():
    j = Tier2LLMJudge(temperature=0.0)   # FROZEN judge — no edits
    data = json.loads((_REPO / "synth" / "partb_validation_set.json").read_text())
    cases = data["cases"]
    # build records the capsule can consume (single-turn)
    prebuilt = []
    for c in cases:
        rec = {"turns": [{"raw_text": c["user_input"], "role": "user"}],
               "structured_action": {"action_type": "unknown", "stated_purpose": None},
               "label": {"is_malicious": not c["ground_truth_consistent"]}}
        prebuilt.append((c, j.build_prompt(rec)))
    tasks = []
    for c, msgs in prebuilt:
        for r in range(N_RUNS):
            tasks.append((c, r, msgs))
    sys.stderr.write(f"PartC: {len(tasks)} calls ({len(cases)} cases x {N_RUNS} runs, "
                    f"workers={WORKERS}). Tier2 FROZEN.\n")
    results = {}
    done = 0; t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        fmap = {ex.submit(_judge_call, m): (cid, r) for (cid, r, m) in tasks}
        for fut in as_completed(fmap):
            c, r = fmap[fut]
            results[(c["id"], r)] = fut.result(); done += 1
            if done % 40 == 0 or done == len(tasks):
                sys.stderr.write(f"  {done}/{len(tasks)} ({time.time()-t0:.0f}s)\n")

    # per-case majority verdict across runs + per-run detail
    cells = []
    for c in cases:
        runs = [results[(c["id"], r)] for r in range(N_RUNS)]
        vdist = Counter(r["verdict"] for r in runs)
        # majority (deterministic tie-break: malicious > suspicious > benign, conservative)
        maj = sorted(vdist.items(), key=lambda kv: (-kv[1], {"malicious":0,"suspicious":1,"benign":2}[kv[0]]))[0][0]
        cells.append({
            "id": c["id"], "category": c["category"], "gt": c["ground_truth_verdict"],
            "majority_verdict": maj, "verdicts_per_run": [r["verdict"] for r in runs],
            "majority_evidence_basis": Counter(r["evidence_basis"] for r in runs).most_common(1)[0][0],
            "majority_pcc": runs[0]["pcc"],
            "reason_majority_run0": runs[0]["reason"],
            "information_gaps_run0": runs[0]["information_gaps"],
            "agreement": len(set(r["verdict"] for r in runs)) == 1,
        })
    out = {"n_cases": len(cases), "n_runs": N_RUNS, "frozen_tier2": True,
           "by_category": dict(Counter(c["category"] for c in cases)), "cells": cells}
    opath = _REPO / "reports" / "v05_partC_frozen_eval.json"
    opath.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    sys.stderr.write(f"written {opath}\n\n")

    # ---- honest summary, split by category ----
    print("=" * 78)
    print("Part C — FROZEN Tier2 on 92-case promptfoo validation set (no 4 hand-made cases)")
    print("=" * 78)
    def stats(subset, label):
        if not subset: return
        n = len(subset)
        # accuracy = majority verdict == gt
        correct = sum(1 for c in subset if c["majority_verdict"] == c["gt"])
        agree = sum(1 for c in subset if c["agreement"])
        # per-run accuracy (averaged)
        per_run = []
        for r in range(N_RUNS):
            ok = sum(1 for c in subset if c["verdicts_per_run"][r] == c["gt"])
            per_run.append(ok / n)
        # evidence_basis distribution
        bas = Counter(c["majority_evidence_basis"] for c in subset)
        # verdict distribution (majority)
        vd = Counter(c["majority_verdict"] for c in subset)
        print(f"\n{label} (n={n}, gt={'benign' if subset[0]['gt']=='benign' else 'malicious'})")
        print(f"  majority-verdict accuracy: {correct}/{n} = {correct/n:.1%}")
        print(f"  per-run accuracy: {[f'{p:.0%}' for p in per_run]} (mean {sum(per_run)/len(per_run):.0%})")
        print(f"  run-to-run agreement (all {N_RUNS} runs same verdict): {agree}/{n} = {agree/n:.0%}")
        print(f"  majority-verdict distribution: {dict(vd)}")
        print(f"  evidence_basis distribution: {dict(bas)}")
        # confusion: how many gt-benign got malicious / gt-malicious got benign
        if label.startswith("consistent (benign"):
            fp = sum(1 for c in subset if c["majority_verdict"]=="malicious")
            print(f"  FALSE POSITIVE (gt benign -> malicious): {fp}/{n} = {fp/n:.0%}")
        else:
            fn = sum(1 for c in subset if c["majority_verdict"]=="benign")
            print(f"  FALSE NEGATIVE (gt malicious -> benign): {fn}/{n} = {fn/n:.0%}")
    cons = [c for c in cells if c["category"] == "consistent"]
    incons = [c for c in cells if c["category"] == "inconsistent"]
    stats(cons, "consistent (scary vocab, benign GT) — expect Tier2 NOT to over-flag")
    stats(incons, "inconsistent (clean purpose, malicious GT) — expect Tier2 to catch the mismatch")
    all_correct = sum(1 for c in cells if c["majority_verdict"] == c["gt"])
    print(f"\n  OVERALL (merged, reported for completeness): {all_correct}/{len(cells)} = {all_correct/len(cells):.1%}")
    print(f"  (per category above is the honest split — do not read the merged number alone)")


if __name__ == "__main__":
    main()
