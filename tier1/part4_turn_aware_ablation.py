"""Part 4: Turn-awareness ablation — does session_length actually help?

Compares two models on the DUAL TRACK:
  - Model WITH session_length (index 18, the current feature set)
  - Model WITHOUT session_length (ablated to constant 0.0)

If session_length helps on the MULTI-TURN track but not the SINGLE-TURN track,
that proves the model leverages turn-awareness exactly where it's useful —
the conditional logic Part 4 asks for. The single-turn track should be
unaffected (session_length is degenerate there anyway).

Usage: python tier1/part4_turn_aware_ablation.py
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
    extract_features, build_benign_profile, FEATURE_NAMES,
)
from tier1.eval_data import load_multiturn_holdout  # noqa: E402
from tier1.prefix_eval import prefixes  # noqa: E402

DATA = _REPOSITORY / "dataset"
REPO = _REPOSITORY
SL_IDX = FEATURE_NAMES.index("session_length")  # 18


def load_jsonl(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def featurize(records, profile, ablate_sl=False):
    X, y = [], []
    for r in records:
        fv = extract_features(r, profile)
        if ablate_sl:
            fv[SL_IDX] = 0.0
        X.append(fv); y.append(int(r["label"]["is_malicious"]))
    return np.array(X), np.array(y)


def featurize_prefixes(records, profile, ablate_sl=False):
    X, y, meta = [], [], []
    for r in records:
        y_full = int(r["label"]["is_malicious"])
        for t, pre in prefixes(r):
            fv = extract_features(pre, profile)
            if ablate_sl:
                fv[SL_IDX] = 0.0
            X.append(fv); y.append(y_full); meta.append(t)
    return np.array(X), np.array(y), meta


def eval_set(model, X, y, name):
    if len(X) == 0 or len(set(y)) < 2:
        return {"n": int(len(y)), "AUC": float("nan"), "note": "empty/single-class"}
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= 0.5).astype(int)
    auc = float(roc_auc_score(y, prob))
    f1 = float(f1_score(y, pred, zero_division=0))
    prec = float(precision_score(y, pred, zero_division=0))
    rec = float(recall_score(y, pred, zero_division=0))
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    print(
        f"    {name}: n={len(y)} AUC={auc:.4f} F1={f1:.4f} Prec={prec:.4f} "
        f"Rec={rec:.4f} TP={tp} FP={fp} TN={tn} FN={fn}",
        file=sys.stderr,
    )
    return {"n": int(len(y)), "AUC": auc, "F1": f1, "Precision": prec,
            "Recall": rec, "TP": tp, "FP": fp, "TN": tn, "FN": fn}


def train_model(X_train, y_train, ablate_sl, label):
    clf = xgb.XGBClassifier(
        n_estimators=180, max_depth=4, use_label_encoder=False,
        eval_metric="logloss", random_state=42,
    )
    clf.fit(X_train, y_train)
    print(f"  trained {label}: train_size={len(X_train)}", file=sys.stderr)
    return clf


def main():
    train = (
        load_jsonl(DATA / "processed" / "train.jsonl")
        + load_jsonl(DATA / "synthetic" / "xgboost_paper_derived.jsonl")
        + load_jsonl(DATA / "synthetic" / "promptfoo_redteam.jsonl")
    )
    benign = [r for r in train if r.get("label", {}).get("is_malicious") is False]
    profile = build_benign_profile(benign)

    # Single-turn test data
    test_indist = load_jsonl(DATA / "processed" / "test_indist.jsonl")
    test_holdout = load_jsonl(DATA / "processed" / "test_holdout_family.jsonl")
    val = load_jsonl(DATA / "processed" / "val.jsonl")
    val_benign = [r for r in val if not r["label"]["is_malicious"]]
    aug_holdout = test_holdout + val_benign

    # Multi-turn holdout (Part 1)
    mt_available = (DATA / "processed" / "test_holdout_multiturn.jsonl").exists()

    print("=" * 72, file=sys.stderr)
    print("Part 4: Turn-awareness ablation (session_length index 18)", file=sys.stderr)
    print("Model WITH session_length  vs  Model WITHOUT (ablated to 0)", file=sys.stderr)
    print("=" * 72, file=sys.stderr)

    # ── Model WITH session_length (current) ──
    print("\n[WITH session_length]", file=sys.stderr)
    X_tr_w, y_tr_w = featurize(train, profile, ablate_sl=False)
    clf_w = train_model(X_tr_w, y_tr_w, False, "WITH")

    # ── Model WITHOUT session_length (ablated) ──
    print("\n[WITHOUT session_length (ablated)]", file=sys.stderr)
    X_tr_wo, y_tr_wo = featurize(train, profile, ablate_sl=True)
    clf_wo = train_model(X_tr_wo, y_tr_wo, True, "WITHOUT")

    results = {"with_session_length": {}, "without_session_length": {}}

    # ── TRACK 1: SINGLE-TURN ──
    print("\n--- TRACK 1: SINGLE-TURN ---", file=sys.stderr)
    X_id_w, y_id_w = featurize(test_indist, profile, False)
    X_id_wo, y_id_wo = featurize(test_indist, profile, True)
    X_aug_w, y_aug_w = featurize(aug_holdout, profile, False)
    X_aug_wo, y_aug_wo = featurize(aug_holdout, profile, True)
    results["with_session_length"]["track1_test_indist"] = eval_set(clf_w, X_id_w, y_id_w, "WITH  test_indist")
    results["without_session_length"]["track1_test_indist"] = eval_set(clf_wo, X_id_wo, y_id_wo, "WO   test_indist")
    results["with_session_length"]["track1_aug_holdout"] = eval_set(clf_w, X_aug_w, y_aug_w, "WITH  aug_holdout")
    results["without_session_length"]["track1_aug_holdout"] = eval_set(clf_wo, X_aug_wo, y_aug_wo, "WO   aug_holdout")

    # ── TRACK 2: MULTI-TURN (prefix level) ──
    print("\n--- TRACK 2: MULTI-TURN (prefix level) ---", file=sys.stderr)
    if mt_available:
        mt_all = load_multiturn_holdout(DATA)["records"]
        X_mt_w, y_mt_w, _ = featurize_prefixes(mt_all, profile, False)
        X_mt_wo, y_mt_wo, _ = featurize_prefixes(mt_all, profile, True)
        results["with_session_length"]["track2_multiturn_prefix"] = eval_set(clf_w, X_mt_w, y_mt_w, "WITH  mt_prefix")
        results["without_session_length"]["track2_multiturn_prefix"] = eval_set(clf_wo, X_mt_wo, y_mt_wo, "WO   mt_prefix")
        # record level for reference
        X_mt_rec_w, y_mt_rec_w = featurize(mt_all, profile, False)
        X_mt_rec_wo, y_mt_rec_wo = featurize(mt_all, profile, True)
        results["with_session_length"]["track2_multiturn_record"] = eval_set(clf_w, X_mt_rec_w, y_mt_rec_w, "WITH  mt_record")
        results["without_session_length"]["track2_multiturn_record"] = eval_set(clf_wo, X_mt_rec_wo, y_mt_rec_wo, "WO   mt_record")
    else:
        print("  (multi-turn holdout not available)", file=sys.stderr)
        results["track2_note"] = "multi-turn holdout not generated"

    # ── session_length importance in both models ──
    imp_w = clf_w.feature_importances_[SL_IDX]
    imp_wo = clf_wo.feature_importances_[SL_IDX]
    results["session_length_importance"] = {
        "with": float(imp_w), "without": float(imp_wo),
    }
    print(f"\nsession_length gain: WITH={imp_w:.6f}  WITHOUT={imp_wo:.6f}", file=sys.stderr)

    # ── delta summary ──
    print("\n" + "=" * 72, file=sys.stderr)
    print("DELTA (WITH - WITHOUT):", file=sys.stderr)
    print("=" * 72, file=sys.stderr)
    for track_key in ["track1_test_indist", "track1_aug_holdout",
                      "track2_multiturn_prefix", "track2_multiturn_record"]:
        w = results["with_session_length"].get(track_key, {})
        wo = results["without_session_length"].get(track_key, {})
        if "AUC" in w and "AUC" in wo and w["AUC"] == w["AUC"]:
            d_auc = w["AUC"] - wo["AUC"]
            d_f1 = w["F1"] - wo["F1"]
            tag = "← turn-awareness helps here" if d_auc > 0.01 else ""
            print(f"  {track_key}: ΔAUC={d_auc:+.4f} ΔF1={d_f1:+.4f} {tag}", file=sys.stderr)

    out = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) > 1
        else REPO / "reports" / "part4_turn_aware_ablation.json"
    )
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nPart 4 ablation written to {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
