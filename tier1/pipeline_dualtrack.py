"""Pipeline end-to-end metrics on the dual tracks (Part 3 supplement).

Runs the full Tier0+Tier1 pipeline (record level) on:
  - TRACK 1: single-turn test sets (test_indist, aug_holdout)
  - TRACK 2: multi-turn holdout (record level — pipeline is record-level)

The pipeline's `run()` gives one decision per record (not prefix-level),
so for multi-turn this is the whole-conversation decision. The Tier-1
prefix-level early-detection is reported separately in part3_dualtrack_eval.json.

Requires TIER0_FORCE_SKLEARN=1 (uses the sklearn TF-IDF index).
"""
import os
import sys
import pathlib
import json

os.environ.setdefault("TIER0_FORCE_SKLEARN", "1")
_REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPOSITORY / "dataset" / "src"))
sys.path.insert(0, str(_REPOSITORY))

from sklearn.metrics import roc_auc_score, f1_score, precision_score, recall_score  # noqa: E402
import numpy as np  # noqa: E402

from pipeline import Pipeline  # noqa: E402
from tier1.eval_data import load_multiturn_holdout  # noqa: E402

DATA = _REPOSITORY / "dataset"
REPO = _REPOSITORY


def load_jsonl(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def pipeline_eval(pipe, records, name):
    """Run pipeline over records, return detection metrics + prob-based AUC."""
    probs, preds, ys = [], [], []
    block = defer = escalate = allow = 0
    for r in records:
        v = pipe.run(r)
        is_mal = bool(r.get("label", {}).get("is_malicious"))
        ys.append(int(is_mal))
        # Any non-release outcome is review-flagged; only allow is cleared.
        pred = 1 if v["final_decision"] in ("block", "defer", "escalate") else 0
        preds.append(pred)
        # use tier1_prob if available else tier0 signal as the score for AUC
        prob = v.get("tier1_prob")
        if prob is None:
            # tier0 only: map final_verdict to a crude score
            tv = v.get("tier0_final", "allow")
            prob = {"malicious": 0.9, "suspicious": 0.6, "benign": 0.1}.get(tv, 0.1)
        probs.append(float(prob))
        if v["final_decision"] == "block":
            block += 1
        elif v["final_decision"] == "defer":
            defer += 1
        elif v["final_decision"] == "escalate":
            escalate += 1
        else:
            allow += 1
    probs = np.array(probs)
    preds = np.array(preds)
    ys = np.array(ys)
    n = len(ys)
    n_mal = int(ys.sum())
    n_ben = n - n_mal
    auc = float(roc_auc_score(ys, probs)) if len(set(ys)) > 1 else float("nan")
    f1 = float(f1_score(ys, preds, zero_division=0))
    prec = float(precision_score(ys, preds, zero_division=0))
    rec = float(recall_score(ys, preds, zero_division=0))
    tp = int(((preds == 1) & (ys == 1)).sum())
    fp = int(((preds == 1) & (ys == 0)).sum())
    tn = int(((preds == 0) & (ys == 0)).sum())
    fn = int(((preds == 0) & (ys == 1)).sum())
    print(
        f"  [pipe:{name}] n={n} mal={n_mal} ben={n_ben} "
        f"AUC={auc:.4f} F1={f1:.4f} Prec={prec:.4f} Rec={rec:.4f} "
        f"block={block} defer={defer} escalate={escalate} allow={allow} "
        f"TP={tp} FP={fp} TN={tn} FN={fn}",
        file=sys.stderr,
    )
    return {
        "n": n, "n_mal": n_mal, "n_ben": n_ben,
        "AUC": auc, "F1": f1, "Precision": prec, "Recall": rec,
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "block": block, "defer": defer, "escalate": escalate, "allow": allow,
    }


def main():
    pipe = Pipeline()

    results = {"track1_single_turn": {}, "track2_multi_turn": {}}

    # ── TRACK 1: SINGLE-TURN ──
    print("=" * 70, file=sys.stderr)
    print("PIPELINE TRACK 1 — SINGLE-TURN", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    test_indist = load_jsonl(DATA / "processed" / "test_indist.jsonl")
    test_holdout = load_jsonl(DATA / "processed" / "test_holdout_family.jsonl")
    val = load_jsonl(DATA / "processed" / "val.jsonl")
    val_benign = [r for r in val if not r["label"]["is_malicious"]]
    aug_holdout = test_holdout + val_benign

    results["track1_single_turn"]["test_indist"] = pipeline_eval(pipe, test_indist, "test_indist")
    results["track1_single_turn"]["aug_holdout"] = pipeline_eval(pipe, aug_holdout, "aug_holdout")

    # ── TRACK 2: MULTI-TURN (record level) ──
    print("=" * 70, file=sys.stderr)
    print("PIPELINE TRACK 2 — MULTI-TURN (record level)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    mt_reviewed_path = DATA / "processed" / "test_holdout_multiturn.jsonl"
    if mt_reviewed_path.exists():
        mt_holdout = load_multiturn_holdout(DATA)
        mt_all = mt_holdout["records"]
        counts = mt_holdout["counts"]
        print(
            f"  multi-turn holdout: {counts['malicious']} mal + "
            f"{counts['benign']} ben = {counts['total']}",
            file=sys.stderr,
        )
        results["track2_multi_turn"]["multiturn_record"] = pipeline_eval(pipe, mt_all, "multiturn_record")
    else:
        print("  (multi-turn holdout not available)", file=sys.stderr)
        results["track2_multi_turn"] = {"note": "not generated"}

    out = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) > 1
        else REPO / "reports" / "part3_pipeline_dualtrack.json"
    )
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"\npipeline dual-track written to {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
