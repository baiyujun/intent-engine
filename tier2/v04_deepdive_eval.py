"""v0.4 deep-dive eval — answer the three follow-up questions with real data.

This is GLUE over the existing judge (no new sample generation). It reuses:
  - Tier2LLMJudge.build_prompt  -> identical Evidence Capsule the real judge sees
  - llm_client.chat(with_reasoning=True) -> surfaces reasoning_content from the
    SAME call that produces the verdict (a 2nd call would decouple verdict from
    reasoning via non-determinism, so it must be one call)
  - llm_client._extract_json + llm_judge._calibrate -> verdict is byte-for-byte what
    Tier2LLMJudge.judge() would return for that call

Three outputs (one JSON: reports/v04_deepdive.json):
  Q1  gate_ext   : 4 cases x 3 variants x N_GATE runs  -> per-case flip/pass rate
                   over a real sample size (not 5). Answers "are the 'stable'
                   cases truly stable, or 5-run luck?"
  Q2  (subset)   : ssh-debug rows carry reasoning_content, bucketed by verdict ->
                   "different evidence each run" (systematic) vs "same doubts,
                   threshold-edge" (gray-zone).
  Q3  disagreement_ext : 22 neutralized samples x N_DIS runs, PER-SAMPLE verdict
                   matrix (part56 computed this but discarded it). Answers "same
                   blind spots, or rotating misses?"

Neutralization is byte-identical to part56_tier2_eval.run_disagreement_samples
(same 6 regexes) so Q3 is comparable to the v0.4 headline number.

Run count / concurrency are env-tunable (V04_GATE_RUNS, V04_DIS_RUNS, V04_WORKERS)
so the run can be re-scoped without editing code. The .env must be sourced
externally (TIER2_LLM_API_KEY) — same as part56.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

os.environ.setdefault("TIER0_FORCE_SKLEARN", "1")
_REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "dataset" / "src"))
sys.path.insert(0, str(_REPO))

from tier2.llm_judge import Tier2LLMJudge, _calibrate          # reuse real judge logic
from tier2.llm_client import chat, _extract_json              # reuse real transport+parse
from tier2.regression_set import (
    load_regression_cases, ground_truth_category, variant_records, VARIANT_KEYS,
)

N_GATE = int(os.environ.get("V04_GATE_RUNS", "18"))
N_DIS = int(os.environ.get("V04_DIS_RUNS", "5"))
WORKERS = int(os.environ.get("V04_WORKERS", "8"))
RETRIES = int(os.environ.get("V04_RETRIES", "2"))

# byte-identical to part56_tier2_eval.run_disagreement_samples neu()
_NEU = [(r"\btests?\b", "checks"), (r"\baudit\b", "review"), (r"\bsecurity\b", "safety"),
       (r"\bcompliance\b", "standards"), (r"\bteam\b", "group"), (r"\binternal\b", "local")]


def _neu(t: str) -> str:
    for p, r_ in _NEU:
        t = re.sub(p, r_, t, flags=re.I)
    return t


def _judge_call(msgs: list[dict], temperature: float = 0.0) -> dict:
    """One judge call mirroring Tier2LLMJudge.judge(), but also keeps reasoning_content.

    Verdict logic is a verbatim mirror of llm_judge.Tier2LLMJudge.judge() so the
    verdict recorded here == what the real judge would return for this exact call.
    """
    last_err = None
    for attempt in range(RETRIES + 1):
        try:
            content, latency_ms, meta = chat(msgs, temperature=temperature,
                                              with_reasoning=True)
            reasoning_content = meta.get("reasoning_content", "")
            parsed = _extract_json(content)
            if parsed is None or "risk_category" not in parsed:
                return {"verdict": "suspicious", "confidence": 0.0, "pcc": None,
                        "reason": f"parse failed (finish={meta.get('finish_reason')}); "
                                  f"honest fallback to suspicious",
                        "reasoning_content": reasoning_content,
                        "finish_reason": meta.get("finish_reason"),
                        "latency_ms": round(latency_ms, 1), "call_ok": True,
                        "parse_ok": False}
            verdict = str(parsed.get("risk_category", "")).strip().lower()
            if verdict not in ("benign", "malicious"):
                return {"verdict": "suspicious", "confidence": 0.0, "pcc": None,
                        "reason": f"unknown risk_category '{verdict}'; fallback",
                        "reasoning_content": reasoning_content,
                        "finish_reason": meta.get("finish_reason"),
                        "latency_ms": round(latency_ms, 1), "call_ok": True,
                        "parse_ok": True}
            pcc = bool(parsed.get("purpose_capability_consistent", True))
            conf = _calibrate(parsed.get("confidence"), verdict=verdict, pcc=pcc)
            reason = str(parsed.get("reason", "") or "")
            return {"verdict": verdict, "confidence": conf, "pcc": pcc,
                    "reason": reason, "reasoning_content": reasoning_content,
                    "finish_reason": meta.get("finish_reason"),
                    "latency_ms": round(latency_ms, 1), "call_ok": True,
                    "parse_ok": True}
        except Exception as e:  # transport/HTTP error -> retry, then honest fallback
            last_err = f"{type(e).__name__}: {e}"
            time.sleep(0.4 * (attempt + 1))
    return {"verdict": "suspicious", "confidence": 0.0, "pcc": None,
            "reason": f"call failed after {RETRIES + 1} attempts: {last_err}",
            "reasoning_content": "", "finish_reason": None,
            "latency_ms": 0.0, "call_ok": False, "parse_ok": False}


def _run_batch(tasks: list[tuple[str, list[dict]]], label: str) -> list[dict]:
    """tasks: list of (cell_id, msgs). Run concurrently, return per-cell results
    in the SAME order (with cell_id attached)."""
    results = [None] * len(tasks)
    done = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        fut_to_idx = {ex.submit(_judge_call, msgs): (i, cid)
                      for i, (cid, msgs) in enumerate(tasks)}
        for fut in as_completed(fut_to_idx):
            i, cid = fut_to_idx[fut]
            r = fut.result()
            r["cell_id"] = cid
            results[i] = r
            done += 1
            if done % 20 == 0 or done == len(tasks):
                el = time.time() - t0
                sys.stderr.write(f"  [{label}] {done}/{len(tasks)} "
                                 f"({el:.0f}s)\n")
    return results


def run_gate_ext(n_runs: int) -> dict:
    j = Tier2LLMJudge(temperature=0.0)
    cases = load_regression_cases()
    # precompute one capsule per (case, variant) — deterministic; reuse across runs
    prebuilt = {}  # (case_id, variant) -> msgs
    for c in cases:
        vrs = variant_records(c)
        for vk in VARIANT_KEYS:
            prebuilt[(c["id"], vk)] = j.build_prompt(vrs[vk])
    tasks = []
    for c in cases:
        gt = ground_truth_category(c)
        for vk in VARIANT_KEYS:
            for r in range(n_runs):
                cid = f"{c['id']}|{vk}|run{r}"
                tasks.append((cid, prebuilt[(c["id"], vk)]))
    sys.stderr.write(f"GATE: {len(cases)} cases x {len(VARIANT_KEYS)} variants x "
                     f"{n_runs} runs = {len(tasks)} calls (workers={WORKERS})\n")
    raw = _run_batch(tasks, "gate")
    # attach metadata + structure per cell
    cells = []
    for c in cases:
        gt = ground_truth_category(c)
        for vk in VARIANT_KEYS:
            for r in range(n_runs):
                cid = f"{c['id']}|{vk}|run{r}"
                res = next(x for x in raw if x["cell_id"] == cid)
                cells.append({"case_id": c["id"], "variant": vk, "run": r,
                              "gt": gt, **{k: v for k, v in res.items()
                                           if k != "cell_id"}})
    return {"n_runs": n_runs, "n_cases": len(cases), "n_variants": len(VARIANT_KEYS),
            "n_calls": len(tasks), "cells": cells}


def run_disagreement_ext(n_runs: int) -> dict:
    src = _REPO / "reports" / "tier2_disagreement_samples.json"
    if not src.exists():
        return {"note": "disagreement samples not found"}
    samples = json.loads(src.read_text())
    j = Tier2LLMJudge(temperature=0.0)
    # precompute one neutralized record + capsule per sample
    prebuilt = []  # (sample, msgs)
    for s in samples:
        rec = {"turns": [{"raw_text": _neu(t), "role": "user"} for t in s["turns"]],
               "structured_action": {"action_type": "unknown", "stated_purpose": None},
               "label": {"is_malicious": s["is_malicious"]}}
        prebuilt.append((s, j.build_prompt(rec)))
    tasks = []
    for si, (s, msgs) in enumerate(prebuilt):
        for r in range(n_runs):
            tasks.append((f"{s['id']}|run{r}", msgs))
    sys.stderr.write(f"DISAGREEMENT: {len(samples)} samples x {n_runs} runs = "
                     f"{len(tasks)} calls (workers={WORKERS})\n")
    raw = _run_batch(tasks, "disagree")
    by_id = {x["cell_id"]: x for x in raw}
    cells = []
    for si, (s, msgs) in enumerate(prebuilt):
        for r in range(n_runs):
            cid = f"{s['id']}|run{r}"
            res = by_id[cid]
            cells.append({"sample_id": s["id"], "is_malicious": bool(s["is_malicious"]),
                          "run": r, **{k: v for k, v in res.items() if k != "cell_id"}})
    return {"n_runs": n_runs, "n_samples": len(samples), "n_calls": len(tasks),
            "cells": cells}


def main():
    t0 = time.time()
    out = {"meta": {"model": "deepseek-v4-pro", "temperature": 0,
                   "n_gate_runs": N_GATE, "n_dis_runs": N_DIS,
                   "workers": WORKERS, "note": "glue over real judge; verdicts "
                   "identical to Tier2LLMJudge.judge(); reasoning_content captured "
                   "from the same call"}}
    sys.stderr.write("=" * 70 + "\nQ1: EXTENDED GATE (4 cases x 3 variants x "
                     f"{N_GATE} runs)\n" + "=" * 70 + "\n")
    out["gate_ext"] = run_gate_ext(N_GATE)
    sys.stderr.write("\n" + "=" * 70 + "\nQ3: DISAGREEMENT PER-SAMPLE (22 x "
                     f"{N_DIS} runs)\n" + "=" * 70 + "\n")
    out["disagreement_ext"] = run_disagreement_ext(N_DIS)
    out["meta"]["elapsed_s"] = round(time.time() - t0, 1)
    outpath = _REPO / "reports" / "v04_deepdive.json"
    outpath.parent.mkdir(exist_ok=True)
    outpath.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    sys.stderr.write(f"\nwritten {outpath} (elapsed {out['meta']['elapsed_s']}s)\n")
    # quick honest stdout summary
    g = out["gate_ext"]
    for cid in sorted({c["case_id"] for c in g["cells"]}):
        runs = [c for c in g["cells"] if c["case_id"] == cid]
        gt = runs[0]["gt"]
        # per-run: are all 3 variants identical AND == gt?
        passruns = 0
        for r in range(N_GATE):
            rv = [c for c in runs if c["run"] == r]
            cats = [c["verdict"] for c in sorted(rv, key=lambda x: VARIANT_KEYS.index(x["variant"]))]
            if len(set(cats)) == 1 and cats[0] == gt:
                passruns += 1
        sys.stderr.write(f"  {cid}: gt={gt} pass {passruns}/{N_GATE}\n")
    d = out["disagreement_ext"]
    mal = [c for c in d["cells"] if c["is_malicious"]]
    sys.stderr.write(f"\n  disagreement malicious per-sample verdicts "
                     f"({len({c['sample_id'] for c in mal})} samples, {N_DIS} runs):\n")
    for sid in sorted({c["sample_id"] for c in mal}):
        vr = [c["verdict"] for c in sorted([c for c in mal if c["sample_id"] == sid],
                                           key=lambda x: x["run"])]
        sys.stderr.write(f"    {sid}: {vr}\n")


if __name__ == "__main__":
    main()
