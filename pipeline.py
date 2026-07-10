"""End-to-end intent-recognition guardrail pipeline (Step 6, FINAL).

Wires Tier 0 (dual-path deterministic judge) -> Tier 1 (XGBoost on 40
features) -> Tier 2 (LLM judge, v0 STUB) -> Tier 3 (orchestrator, v0 STUB)
into a single callable :class:`Pipeline`.

Because Tier 2 and Tier 3 are documented ``not_implemented`` stubs in v0,
the final decision is produced by :meth:`Pipeline._decide` — a documented
fallback policy that stands in for the stubbed Tier 3 orchestrator. v0.3
introduced **tiered confidence gating** (see reports/part1_tiered_fusion.md):

    * tier0 malicious                                    -> ``block``
    * tier0 suspicious AND tier1 prob >= 0.5            -> ``block``
    * tier0 suspicious (else)                            -> ``escalate``
    * tier0 benign AND tier1 prob >= 0.5                 -> ``defer`` (review)
    * tier0 benign AND tier1 prob in [0.4, 0.5)          -> ``escalate``
    * otherwise                                          -> ``allow``

The v0.2 union rule (tier0 malicious OR tier1 prob>=0.5 -> block) caused a
40% benign hard-block false-positive on multi-turn because Tier0-benign cases
were hard-blocked by Tier1 alone; the gate fixes it (benign-FP 40% -> 2.5%).

CLI:
    python -m pipeline --input "<text>"                 # single text
    python -m pipeline --input <path.jsonl>             # batch
    python -m pipeline --evaluate test_indist|test_holdout|all
"""
from __future__ import annotations

import os
import sys
import pathlib
import json
import time
import argparse

# ── self-contained import shim ───────────────────────────────────────────────
_ROOT = pathlib.Path(__file__).resolve().parent
_DATASET = _ROOT / "dataset"
_DS = _DATASET / "src"
for _p in (str(_ROOT), str(_DS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from schema import canonical_text  # noqa: E402
from tier0.fusion import judge as tier0_judge  # noqa: E402
from tier1.features import extract_features, build_benign_profile, FEATURE_NAMES  # noqa: E402
from tier2 import Tier2LLMJudge  # noqa: E402
from tier2.base import Tier2Verdict  # noqa: E402
from tier3 import Tier3Orchestrator  # noqa: E402

# ── data paths (dataset is now in-repo under dataset/) ────────────────────────
TRAIN_REAL = _DATASET / "processed" / "train.jsonl"
TRAIN_SYNTH = _DATASET / "synthetic" / "xgboost_paper_derived.jsonl"
TEST_INDIST = _DATASET / "processed" / "test_indist.jsonl"
TEST_HOLDOUT = _DATASET / "processed" / "test_holdout_family.jsonl"

PIPELINE_VERDICT_KEYS = (
    "id",
    "tier0_final",
    "tier0_escalated",
    "tier0_ms",
    "tier1_invoked",
    "tier1_prob",
    "tier1_ms",
    "tier2_status",
    "tier3_status",
    "final_decision",
    "tier_used",
    "total_ms",
)


def load_jsonl(path):
    """Load a JSONL file into a list of dicts (skips blank lines)."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


class Pipeline:
    """End-to-end guardrail orchestrator.

    Loads the Tier 1 XGBoost model + builds the benign feature profile once
    (from training benign records). Tier 0's FAISS/MiniLM index is loaded
    lazily on the first :meth:`run` call (one-time ~18s MiniLM load, then
    ~36ms/query steady-state — or the fast sklearn backend under
    ``TIER0_FORCE_SKLEARN=1``, the conftest default for tests).

    Tier 2 (``Tier2LLMJudge``) and Tier 3 (``Tier3Orchestrator``) are v0
    stubs returning ``not_implemented``; the final decision therefore
    comes from :meth:`_decide`, a documented fallback over Tier 0 + Tier 1.
    """

    def __init__(self, models_dir="tier0/models", tier1_model="tier1/models/xgboost_full.json",
                 tier2_enabled: bool = False):
        import xgboost as xgb

        self.models_dir = models_dir
        # Tier 2 is a REAL LLM judge in v0.4, but OFF by default (no network call /
        # latency in tests or the Tier0+Tier1 baseline). Set tier2_enabled=True to
        # actually call the LLM (Part 6 eval). When off, .run reports
        # tier2_status="not_implemented" exactly as the v0 stub did.
        self.tier2_enabled = tier2_enabled

        # ── Tier 1 model ──────────────────────────────────────────────────
        tier1_path = pathlib.Path(tier1_model)
        if not tier1_path.exists():
            raise FileNotFoundError(
                f"Tier 1 model not found at {tier1_path}. "
                "Run `python -m tier1.train` first to build it."
            )
        self.clf = xgb.XGBClassifier()
        self.clf.load_model(str(tier1_path))

        # ── benign profile (built ONCE from training benign records) ──────
        self.profile = self._build_profile()

        # ── Tier 2 / Tier 3 ───────────────────────────────────────────────
        self.tier2 = Tier2LLMJudge()
        self.tier3 = Tier3Orchestrator()

    @staticmethod
    def _build_profile() -> dict:
        """Load train_real + train_synth, keep benign, build the profile."""
        records = []
        for p in (TRAIN_REAL, TRAIN_SYNTH):
            if p.exists():
                records.extend(load_jsonl(p))
        benign = [r for r in records if r.get("label", {}).get("is_malicious") is False]
        return build_benign_profile(benign)

    # ── fallback decision policy (stands in for the stubbed Tier 3) ──────────
    def _decide(self, t0, tier1_invoked: bool, prob: float | None) -> str:
        """Tiered fusion fallback (v0.3). Matches INTENDED_POLICY (Tier 3 stub).

        v0.2 BUG (the multi-turn benign red line): the old union rule did
        ``tier0 malicious OR (tier1 prob >= 0.5) -> block``. When Tier0
        returned ``benign`` but ``escalated=True`` (fuzzy zone), Tier1 was
        invoked and its prob>=0.5 -> hard block, IGNORING Tier0's benign lean.
        On multi-turn benign this caused 40% hard-block FP (Tier0 alone 7.5%).

        v0.3 FIX — gate Tier1's hard-block by Tier0's OWN verdict:
          * tier0 malicious                                  -> block
          * tier0 suspicious AND tier1 prob >= P_SUSP_BLOCK  -> block
          * tier0 suspicious (else)                          -> escalate
          * tier0 benign AND tier1 prob >= P_BENIGN_HARD    -> defer (review)
          * tier0 benign AND tier1 prob >= P_BENIGN_SOFT    -> escalate
          * tier0 benign (else)                             -> allow
        When Tier0 leans benign, Tier1's high prob can only DEFER (human
        review), never auto-block. See reports/part1_tiered_fusion.md.
        """
        P_SUSP_BLOCK = 0.5
        P_BENIGN_HARD = 0.5
        P_BENIGN_SOFT = 0.4
        v = t0.final_verdict
        if v == "malicious":
            return "block"
        if v == "suspicious":
            if tier1_invoked and prob is not None and prob >= P_SUSP_BLOCK:
                return "block"
            return "escalate"
        # v == "benign": Tier1's high prob may only DEFER, not block
        if tier1_invoked and prob is not None:
            if prob >= P_BENIGN_HARD:
                return "defer"
            if prob >= P_BENIGN_SOFT:
                return "escalate"
        return "allow"

    def run(self, record: dict) -> dict:
        """Run the full pipeline on a single record; return a PipelineVerdict."""
        rid = record.get("id", "?")
        text = canonical_text(record)

        # ── Tier 0 (lazy FAISS/sklearn load on first call) ─────────────────
        t0 = tier0_judge(text, models_dir=self.models_dir, text_only=True)

        tier1_invoked = bool(t0.escalated or t0.final_verdict in ("suspicious", "malicious"))

        prob = None
        t1_ms = 0.0
        if tier1_invoked:
            t1_start = time.perf_counter()
            fv = extract_features(record, self.profile)
            prob = float(self.clf.predict_proba([fv])[0, 1])
            t1_ms = (time.perf_counter() - t1_start) * 1000.0

        # ── Tier 2 (real LLM in v0.4, but gated OFF by default) ────────────
        if self.tier2_enabled:
            t2 = self.tier2.judge(record, tier1_prob=prob,
                                  tier1_features=fv if tier1_invoked else None)
        else:
            # no network call in the default/baseline path — behaves as the v0 stub
            t2 = Tier2Verdict(status="not_implemented", score=0.0, confidence=0.0,
                             reasoning="tier2 disabled (default; no LLM call)",
                             model=self.tier2.model, latency_ms=0.0)
        t3 = self.tier3.orchestrate(t0, prob if tier1_invoked else None, t2)

        final = self._decide(t0, tier1_invoked, prob)
        # tier2 default-off / tier3 stub => highest REAL tier is 0 or 1
        tier_used = "tier1" if tier1_invoked else "tier0"

        # total_ms: t0.total already covers t0 wall-clock; add t1 if invoked.
        # (t2/t3 stubs add ~0; we do not double-count t0.)
        total_ms = t0.total_ms + t1_ms

        return {
            "id": rid,
            "tier0_final": t0.final_verdict,
            "tier0_escalated": t0.escalated,
            "tier0_ms": t0.total_ms,
            "tier1_invoked": tier1_invoked,
            "tier1_prob": prob,
            "tier1_ms": t1_ms,
            "tier2_status": t2.status,
            "tier3_status": t3.status,
            "final_decision": final,
            "tier_used": tier_used,
            "total_ms": total_ms,
        }

    # ── evaluation ───────────────────────────────────────────────────────────
    def evaluate(self, jsonl_path: str) -> dict:
        """Run over a test set and compute detection + latency metrics.

        decision_to_pred (review-recall view): block/escalate/defer -> 1
        (all three are "not cleared" — a defer goes to human review, so it
        still catches a malicious case). allow -> 0.

        Separately reports hard_block (block only) for the v0.3 red-line metric:
        the benign hard-block false-positive (defer is NOT an auto-block).
        """
        records = load_jsonl(jsonl_path)

        n = 0
        n_malicious = 0
        n_benign = 0
        tp = fp = tn = fn = 0
        block = escalate = defer = allow = 0
        # hard-block confusion (block only)
        hb_tp = hb_fp = hb_tn = hb_fn = 0
        tier1_invoked_count = 0
        latencies = []

        for r in records:
            v = self.run(r)
            n += 1
            is_mal = bool(r.get("label", {}).get("is_malicious"))
            if is_mal:
                n_malicious += 1
            else:
                n_benign += 1

            # review-recall view: block/escalate/defer all count as flagged
            pred = 1 if v["final_decision"] in ("block", "escalate", "defer") else 0
            if v["tier1_invoked"]:
                tier1_invoked_count += 1
            if v["final_decision"] == "block":
                block += 1
            elif v["final_decision"] == "escalate":
                escalate += 1
            elif v["final_decision"] == "defer":
                defer += 1
            else:
                allow += 1
            latencies.append(v["total_ms"])

            if pred == 1 and is_mal:
                tp += 1
            elif pred == 1 and not is_mal:
                fp += 1
            elif pred == 0 and not is_mal:
                tn += 1
            else:  # pred == 0 and is_mal
                fn += 1

            # hard-block confusion (block only) — the red-line metric
            hb = 1 if v["final_decision"] == "block" else 0
            if hb and is_mal:
                hb_tp += 1
            elif hb and not is_mal:
                hb_fp += 1
            elif not hb and not is_mal:
                hb_tn += 1
            else:
                hb_fn += 1

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        accuracy = (tp + tn) / n if n else 0.0
        # detection_rate: fraction of malicious records flagged (block/escalate/defer)
        detection_rate = tp / n_malicious if n_malicious else 0.0
        block_rate = block / n if n else 0.0
        escalate_rate = escalate / n if n else 0.0
        defer_rate = defer / n if n else 0.0
        tier1_invocation_rate = tier1_invoked_count / n if n else 0.0
        # hard-block metrics (the v0.3 red-line: benign hard-block FP)
        hardblock_benign_fp = hb_fp / n_benign if n_benign else 0.0
        hardblock_recall = hb_tp / n_malicious if n_malicious else 0.0

        latencies_sorted = sorted(latencies)

        def _pct(q):
            if not latencies_sorted:
                return 0.0
            # nearest-rank percentile
            idx = max(0, min(len(latencies_sorted) - 1, int(round(q * (len(latencies_sorted) - 1)))))
            return latencies_sorted[idx]

        return {
            "n": n,
            "n_malicious": n_malicious,
            "n_benign": n_benign,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "detection_rate": detection_rate,
            "block_rate": block_rate,
            "escalate_rate": escalate_rate,
            "defer_rate": defer_rate,
            "hardblock_recall": hardblock_recall,
            "hardblock_benign_fp": hardblock_benign_fp,
            "tier1_invocation_rate": tier1_invocation_rate,
            "p50_ms": _pct(0.50),
            "p90_ms": _pct(0.90),
            "max_ms": latencies_sorted[-1] if latencies_sorted else 0.0,
        }


# ── minimal record builder for single-text CLI mode ──────────────────────────
def _minimal_record(text: str) -> dict:
    """Build a minimal schema-shaped record so canonical_text + features work."""
    return {
        "turns": [
            {
                "turn_index": 0,
                "role": "user",
                "raw_text": text,
                "instruction_origin": "user_direct",
            }
        ],
        "structured_action": {
            "action_type": "unknown",
            "target_resource": None,
            "stated_purpose": None,
        },
        "label": {
            "is_malicious": False,
            "attack_family": "benign",
            "risk_category": "benign",
            "purpose_capability_consistent": True,
            "confidence": "high",
        },
    }


def _print_metrics_table(name: str, m: dict) -> None:
    print(f"\n=== {name} ===")
    print(f"  n={m['n']}  malicious={m['n_malicious']}  benign={m['n_benign']}")
    print(
        f"  tp={m['tp']} fp={m['fp']} tn={m['tn']} fn={m['fn']}"
        f"  | prec={m['precision']:.4f} rec={m['recall']:.4f} "
        f"f1={m['f1']:.4f} acc={m['accuracy']:.4f}"
    )
    print(
        f"  detection_rate={m['detection_rate']:.4f}  block_rate={m['block_rate']:.4f}  "
        f"escalate_rate={m['escalate_rate']:.4f}  tier1_invocation_rate={m['tier1_invocation_rate']:.4f}"
    )
    print(
        f"  latency p50={m['p50_ms']:.2f}ms  p90={m['p90_ms']:.2f}ms  max={m['max_ms']:.2f}ms"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Intent-recognition guardrail pipeline (v0)")
    parser.add_argument("--input", help="single text or path to a .jsonl file")
    parser.add_argument(
        "--evaluate",
        choices=["test_indist", "test_holdout", "all"],
        help="run evaluation over a test set (or both) and write reports/pipeline_results.json",
    )
    parser.add_argument("--output", choices=["json", "summary"], default="summary")
    parser.add_argument("--models-dir", default="tier0/models")
    parser.add_argument("--tier1-model", default="tier1/models/xgboost_full.json")
    args = parser.parse_args(argv)

    # graceful handling of missing artifacts
    try:
        pipe = Pipeline(models_dir=args.models_dir, tier1_model=args.tier1_model)
    except FileNotFoundError as e:
        msg = str(e)
        if "tier0" in msg.lower() or "faiss" in msg.lower():
            print(
                "ERROR: Tier 0 models not found. Rebuild the index first:\n"
                "  python -m tier0.run --build-index --train-path <path>",
                file=sys.stderr,
            )
        else:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    # ── evaluate mode ────────────────────────────────────────────────────────
    if args.evaluate:
        results = {}
        if args.evaluate in ("test_indist", "all"):
            try:
                m = pipe.evaluate(str(TEST_INDIST))
            except FileNotFoundError:
                print(
                    f"ERROR: test set not found at {TEST_INDIST}", file=sys.stderr
                )
                return 1
            results["test_indist"] = m
            _print_metrics_table("test_indist", m)
        if args.evaluate in ("test_holdout", "all"):
            try:
                m = pipe.evaluate(str(TEST_HOLDOUT))
            except FileNotFoundError:
                print(
                    f"ERROR: test set not found at {TEST_HOLDOUT}", file=sys.stderr
                )
                return 1
            results["test_holdout"] = m
            _print_metrics_table("test_holdout", m)

        if args.output == "json":
            print(json.dumps(results, indent=2))

        # write reports/pipeline_results.json
        report_path = _ROOT / "reports" / "pipeline_results.json"
        report_path.parent.mkdir(exist_ok=True)
        # record which tier0 backend was used. Match tier0.vector_index._force_sklearn:
        # the real FAISS+MiniLM backend is the DEFAULT (env unset/empty -> faiss);
        # TIER0_FORCE_SKLEARN in {1,true,yes} selects the fast sklearn backend.
        _fs = os.environ.get("TIER0_FORCE_SKLEARN", "").strip().lower()
        backend = "sklearn" if _fs in ("1", "true", "yes") else "faiss_minilm"
        out = {"tier0_backend": backend, "results": results}
        report_path.write_text(json.dumps(out, indent=2))
        print(f"\nMetrics written to {report_path}", file=sys.stderr)
        return 0

    # ── input mode (single text or batch jsonl) ──────────────────────────────
    if args.input:
        inp = pathlib.Path(args.input)
        if inp.exists() and inp.suffix == ".jsonl":
            # batch
            records = load_jsonl(str(inp))
            for r in records:
                v = pipe.run(r)
                if args.output == "json":
                    print(json.dumps(v))
                else:
                    print(
                        f"{v['id']}: {v['final_decision']} "
                        f"(tier0={v['tier0_final']}, tier1_invoked={v['tier1_invoked']}, "
                        f"prob={v['tier1_prob']}, {v['total_ms']:.2f}ms)"
                    )
            return 0
        else:
            # single text
            v = pipe.run(_minimal_record(args.input))
            print(json.dumps(v, indent=2))
            return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
