"""Dual-track evaluation (Part 3): single-turn and multi-turn evaluated SEPARATELY.

NEVER merge into one combined metric. Each track reports:
  - Tier-1 XGBoost metrics (AUC/F1/Precision/Recall)
  - Pipeline end-to-end metrics (Tier0 ∪ Tier1)

TRACK 1 — SINGLE-TURN:
  Uses the existing single-turn test sets (test_indist, test_holdout_family).
  These are 100% public-dataset, 100% single-turn (Part 2 audit).
  Evaluated at record level (each record = 1 prefix anyway).
  Measures: can the model detect single-turn adversarial prompts?

TRACK 2 — MULTI-TURN:
  Uses the NEW promptfoo GOAT/Crescendo multi-turn holdout (Part 1).
  Evaluated at PREFIX level (the paper's core eval): for each t-turn attack,
  every partial history S1:t is an eval instance labeled by the whole-interaction
  outcome. This is where "flag-before-harm" and turn-awareness actually apply.
  Benign multi-turn controls from Part 1 are the y=0 class.

The two tracks answer different questions and must NOT be combined.
"""
import sys
import pathlib
import json

_REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPOSITORY / "dataset" / "src"))
sys.path.insert(0, str(_REPOSITORY))

import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    roc_auc_score, f1_score, precision_score, recall_score,
)

from tier1.features import (  # noqa: E402
    extract_features, build_benign_profile, FEATURE_NAMES, FEATURE_GROUPS,
)
from tier1.eval_data import load_multiturn_holdout  # noqa: E402
from tier1.prefix_eval import prefixes  # noqa: E402


DATA = _REPOSITORY / "dataset"
REPO = _REPOSITORY


def load_jsonl(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def featurize_records(records, profile):
    X, y, errs = [], [], []
    for r in records:
        try:
            fv = extract_features(r, profile)
            X.append(fv); y.append(int(r["label"]["is_malicious"]))
        except Exception as e:
            errs.append(str(e))
    return np.array(X), np.array(y), errs


def featurize_prefixes(records, profile):
    """Prefix-level featurization: each prefix S1:t is an eval instance."""
    X, y, meta = [], [], []
    for r in records:
        y_full = int(r["label"]["is_malicious"])
        rid = r.get("id", "?")
        for t, pre in prefixes(r):
            fv = extract_features(pre, profile)
            X.append(fv); y.append(y_full); meta.append((rid, t, y_full))
    return np.array(X), np.array(y), meta


def metrics(X, y, name):
    if len(X) == 0 or len(set(y)) < 2:
        return {"n": len(X), "AUC": float("nan"), "F1": 0, "Precision": 0,
                "Recall": 0, "note": "insufficient or single-class"}
    prob = None
    # predict_proba handled by caller
    return None  # placeholder; actual metrics computed with model


def eval_with_model(model, X, y, name):
    if len(X) == 0:
        return {"n": 0, "AUC": float("nan"), "note": "empty"}
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= 0.5).astype(int)
    if len(set(y)) < 2:
        auc = float("nan")
    else:
        auc = float(roc_auc_score(y, prob))
    f1 = float(f1_score(y, pred, zero_division=0))
    prec = float(precision_score(y, pred, zero_division=0))
    rec = float(recall_score(y, pred, zero_division=0))
    det = float(pred.sum() / len(pred)) if len(pred) else 0.0
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    print(
        f"  [{name}] n={len(y)} mal={int(y.sum())} ben={int((~y.astype(bool)).sum())} "
        f"AUC={auc:.4f} F1={f1:.4f} Prec={prec:.4f} Rec={rec:.4f} "
        f"TP={tp} FP={fp} TN={tn} FN={fn}",
        file=sys.stderr,
    )
    return {
        "n": int(len(y)), "n_mal": int(y.sum()), "n_ben": int((~y.astype(bool)).sum()),
        "AUC": auc, "F1": f1, "Precision": prec, "Recall": rec,
        "DetectionRate": det, "TP": tp, "FP": fp, "TN": tn, "FN": fn,
    }


def main():
    # ── load training data + build profile ──
    train = (
        load_jsonl(DATA / "processed" / "train.jsonl")
        + load_jsonl(DATA / "synthetic" / "xgboost_paper_derived.jsonl")
        + load_jsonl(DATA / "synthetic" / "promptfoo_redteam.jsonl")
    )
    benign = [r for r in train if r.get("label", {}).get("is_malicious") is False]
    profile = build_benign_profile(benign)

    # ── load model ──
    model = xgb.XGBClassifier()
    model.load_model(str(REPO / "tier1" / "models" / "xgboost_full.json"))

    # ════════════════════════════════════════════════════════════════════════
    # TRACK 1 — SINGLE-TURN (record level, existing public test sets)
    # ════════════════════════════════════════════════════════════════════════
    print("=" * 70, file=sys.stderr)
    print("TRACK 1 — SINGLE-TURN (record level, public datasets)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    test_indist = load_jsonl(DATA / "processed" / "test_indist.jsonl")
    test_holdout = load_jsonl(DATA / "processed" / "test_holdout_family.jsonl")
    # aug_holdout = holdout mal + val benign (the v0.1 metric)
    val = load_jsonl(DATA / "processed" / "val.jsonl")
    val_benign = [r for r in val if not r["label"]["is_malicious"]]
    aug_holdout = test_holdout + val_benign

    X_id, y_id, _ = featurize_records(test_indist, profile)
    X_aug, y_aug, _ = featurize_records(aug_holdout, profile)

    track1 = {
        "test_indist": eval_with_model(model, X_id, y_id, "single:test_indist"),
        "aug_holdout": eval_with_model(model, X_aug, y_aug, "single:aug_holdout"),
    }

    # ════════════════════════════════════════════════════════════════════════
    # TRACK 2 — MULTI-TURN (prefix level, new promptfoo holdout)
    # ════════════════════════════════════════════════════════════════════════
    print("=" * 70, file=sys.stderr)
    print("TRACK 2 — MULTI-TURN (prefix level, promptfoo GOAT/Crescendo holdout)",
          file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    track2 = {"note": "multi-turn holdout not yet generated"}
    if (DATA / "processed" / "test_holdout_multiturn.jsonl").exists():
        mt_holdout = load_multiturn_holdout(DATA)
        mt_all = mt_holdout["records"]
        counts = mt_holdout["counts"]
        print(
            f"  multi-turn holdout: {counts['malicious']} mal + "
            f"{counts['benign']} ben = {counts['total']}",
            file=sys.stderr,
        )
        # turn-count distribution
        from collections import Counter
        tc = Counter(len(r.get("turns", [])) for r in mt_all)
        print(f"  turn-count distribution: {dict(sorted(tc.items()))}", file=sys.stderr)

        # Prefix-level eval (the paper's core: flag before harm)
        X_mt, y_mt, meta_mt = featurize_prefixes(mt_all, profile)
        # Per-prefix session_length distribution (proves turn variation)
        sl_idx = FEATURE_NAMES.index("session_length")
        sl_vals = X_mt[:, sl_idx]
        sl_dist = Counter(int(v) for v in sl_vals)
        print(
            f"  prefixes: {len(X_mt)} (mal={int(y_mt.sum())} ben={int((~y_mt.astype(bool)).sum())})",
            file=sys.stderr,
        )
        print(
            f"  prefix session_length distribution: {dict(sorted(sl_dist.items()))}",
            file=sys.stderr,
        )
        track2 = {
            "prefix": eval_with_model(model, X_mt, y_mt, "multi:prefix"),
            "n_records": len(mt_all),
            "n_mal_records": counts["malicious"],
            "n_ben_records": counts["benign"],
            "n_reviewed_records": counts["reviewed"],
            "n_legacy_benign_records": counts["legacy_benign"],
            "prefix_session_length_dist": dict(sorted(sl_dist.items())),
        }
        # Also record-level (whole conversation) for completeness, but prefix is primary
        X_mt_rec, y_mt_rec, _ = featurize_records(mt_all, profile)
        track2["record_level_for_reference"] = eval_with_model(
            model, X_mt_rec, y_mt_rec, "multi:record(ref)"
        )
    else:
        print("  (multi-turn holdout file not found — run Part 1 first)", file=sys.stderr)

    # ── write report ──
    out = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) > 1
        else REPO / "reports" / "part3_dualtrack_eval.json"
    )
    out.parent.mkdir(exist_ok=True)
    results = {
        "track1_single_turn": track1,
        "track2_multi_turn": track2,
        "IMPORTANT": "These two tracks are NEVER combined into one metric.",
        "feature_importances": {
            FEATURE_NAMES[i]: float(model.feature_importances_[i])
            for i in range(len(FEATURE_NAMES))
        },
    }
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"\ndual-track eval written to {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
