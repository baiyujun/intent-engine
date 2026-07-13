"""v0.5 Part 6 — regression gate: confirm the prompt/capsule changes did NOT regress the
v0.4 achievement (scary-word FP reduced to ~96%). Re-run the 4 semantic-robustness gate
cases × 3 variants × N runs with the NEW judge, and check:
  1. The 3 truly-benign cases (secure-log, secure-tokens, ms-2-redact) still pass robustly
     (don't flip to malicious on the scary variant) — NO scary-FP regression.
  2. ssh-debug's status with the new prompt (verdict + evidence_basis).
  3. Overall gate pass rate vs v0.4 (which was 1/5 = 20%).
Gate pass per run = all 4 cases: 3 variants same verdict category AND match GT.
This is glue over the real judge (build_prompt + _extract_json + _calibrate).
"""
from __future__ import annotations

import json
import os
import pathlib
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
from tier2.regression_set import (
    load_regression_cases, ground_truth_category, variant_records, VARIANT_KEYS,
)

N_RUNS = int(os.environ.get("V05P6_RUNS", "8"))
WORKERS = int(os.environ.get("V05P6_WORKERS", "12"))
RETRIES = int(os.environ.get("V05_RETRIES", "4"))


def _judge_call(msgs, temperature=0.0):
    last = None
    for _ in range(RETRIES + 1):
        try:
            content, _, meta = chat(msgs, temperature=temperature, with_reasoning=False)
            parsed = _extract_json(content)
            if parsed is None or "risk_category" not in parsed:
                return {"verdict": "suspicious", "confidence": 0.0,
                        "evidence_basis": "information_gap"}
            v = str(parsed.get("risk_category", "")).strip().lower()
            if v not in ("benign", "malicious"):
                return {"verdict": "suspicious", "confidence": 0.0,
                        "evidence_basis": "information_gap"}
            pcc = bool(parsed.get("purpose_capability_consistent", True))
            conf = _calibrate(parsed.get("confidence"), verdict=v, pcc=pcc)
            basis = str(parsed.get("evidence_basis", "") or "").strip().lower()
            if basis not in ("grounded", "information_gap"):
                basis = "grounded"
            return {"verdict": v, "confidence": conf, "evidence_basis": basis}
        except Exception as e:
            last = f"{type(e).__name__}: {e}"; time.sleep(0.4)
    return {"verdict": "suspicious", "confidence": 0.0, "evidence_basis": "information_gap"}


def main():
    j = Tier2LLMJudge(temperature=0.0)
    cases = load_regression_cases()
    prebuilt = {}
    for c in cases:
        for vk in VARIANT_KEYS:
            prebuilt[(c["id"], vk)] = j.build_prompt(variant_records(c)[vk])
    tasks = []
    for c in cases:
        for vk in VARIANT_KEYS:
            for r in range(N_RUNS):
                tasks.append((c["id"], vk, r, prebuilt[(c["id"], vk)]))
    sys.stderr.write(f"Part6 regression: {len(tasks)} calls ({len(cases)} cases x "
                    f"{len(VARIANT_KEYS)} variants x {N_RUNS} runs, workers={WORKERS})\n")
    results = {}
    done = 0; t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        fmap = {ex.submit(_judge_call, m): (cid, vk, r) for (cid, vk, r, m) in tasks}
        for fut in as_completed(fmap):
            cid, vk, r = fmap[fut]
            results[(cid, vk, r)] = fut.result(); done += 1
            if done % 30 == 0 or done == len(tasks):
                sys.stderr.write(f"  {done}/{len(tasks)} ({time.time()-t0:.0f}s)\n")

    out = {"n_runs": N_RUNS, "cells": []}
    for (cid, vk, r), res in results.items():
        out["cells"].append({"case_id": cid, "variant": vk, "run": r, **res})
    opath = _REPO / "reports" / "v05_part6_regression.json"
    opath.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    sys.stderr.write(f"written {opath}\n\n")

    print("=" * 78)
    print("Part 6 — REGRESSION GATE (new prompt, did scary-FP come back?)")
    print("=" * 78)
    case_ids = sorted({c["id"] for c in cases})
    pass_runs = 0
    for cid in case_ids:
        gt = ground_truth_category(next(c for c in cases if c["id"] == cid))
        runs_pass = 0; flip_safe = 0
        per_var = {vk: Counter() for vk in VARIANT_KEYS}
        per_var_basis = {vk: Counter() for vk in VARIANT_KEYS}
        for r in range(N_RUNS):
            cats = [results[(cid, vk, r)]["verdict"] for vk in VARIANT_KEYS]
            basises = [results[(cid, vk, r)]["evidence_basis"] for vk in VARIANT_KEYS]
            for vk, cat in zip(VARIANT_KEYS, cats):
                per_var[vk][cat] += 1
            for vk, b in zip(VARIANT_KEYS, basises):
                per_var_basis[vk][b] += 1
            if len(set(cats)) == 1:
                flip_safe += 1
            if len(set(cats)) == 1 and cats[0] == gt:
                runs_pass += 1
        print(f"\n{cid} (gt={gt})")
        print(f"  gate pass (3 variants agree AND ==gt): {runs_pass}/{N_RUNS}")
        print(f"  flip_safe (3 variants agree): {flip_safe}/{N_RUNS}")
        for vk in VARIANT_KEYS:
            print(f"  {vk:13s}: verdicts={dict(per_var[vk])} basis={dict(per_var_basis[vk])}")
    # overall gate pass rate
    allpass = 0
    for r in range(N_RUNS):
        ok = all(len(set([results[(cid, vk, r)]["verdict"] for vk in VARIANT_KEYS])) == 1
                 and results[(cid, VARIANT_KEYS[0], r)]["verdict"] == ground_truth_category(next(c for c in cases if c["id"] == cid))
                 for cid in case_ids)
        if ok:
            allpass += 1
    print(f"\n  GATE (all 4 pass): {allpass}/{N_RUNS} = {allpass/N_RUNS:.0%}  (v0.4 was 1/5 = 20%)")


if __name__ == "__main__":
    main()
