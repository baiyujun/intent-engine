"""Tier 1 XGBoost training / evaluation / ablation script.

Reads real + synthetic training data, builds a benign profile, extracts 40
features, trains an XGBClassifier with two paper-aligned parameters
(n_estimators=180, max_depth=4) and XGBoost defaults for the rest,
evaluates on test_indist and test_holdout_family, then runs a
leave-one-out ablation of the local fraud-inspired group (cols 31-39).

Outputs:
  tier1/models/xgboost_full.json    — full 40-feature model
  tier1/models/xgboost_ablated.json — 31-feature model (fraud group dropped)
  reports/tier1_results.json        — metrics + ablation deltas
"""
import os
import sys
import pathlib
import json

# ── self-contained import shim ───────────────────────────────────────────────
_REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPOSITORY / "dataset" / "src"))
sys.path.insert(0, str(_REPOSITORY))

from schema import validate_record  # noqa: E402
from tier1.features import (  # noqa: E402
    extract_features,
    build_benign_profile,
    FEATURE_NAMES,
    FEATURE_GROUPS,
)
import xgboost as xgb  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    roc_auc_score,
    f1_score,
    precision_score,
    recall_score,
)
import numpy as np  # noqa: E402


def load_jsonl(path):
    """Load a JSONL file into a list of dicts."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main():
    DATA = _REPOSITORY / "dataset"
    repo = _REPOSITORY

    # 1. Load data
    train_real = load_jsonl(DATA / "processed/train.jsonl")
    train_synth = load_jsonl(DATA / "synthetic/xgboost_paper_derived.jsonl")
    # Dilution source: promptfoo redteam adversarial inputs (LLM-generated,
    # non-templated) — added to break the synthetic-template fingerprints
    # (e.g. the benign "summarize" keyword that leaked into tool_summarize).
    pf_path = DATA / "synthetic" / "promptfoo_redteam.jsonl"
    train_promptfoo = load_jsonl(pf_path) if pf_path.exists() else []
    train_all = train_real + train_synth + train_promptfoo

    test_indist = load_jsonl(DATA / "processed/test_indist.jsonl")
    test_holdout = load_jsonl(DATA / "processed/test_holdout_family.jsonl")

    print(
        f"Train: {len(train_real)} real + {len(train_synth)} synth "
        f"+ {len(train_promptfoo)} promptfoo = {len(train_all)} total",
        file=sys.stderr,
    )
    print(
        f"Test in-dist: {len(test_indist)}, "
        f"Test holdout: {len(test_holdout)}",
        file=sys.stderr,
    )

    # 2. Build benign profile from TRAINING benign records only
    benign_records = [
        r for r in train_all if r.get("label", {}).get("is_malicious") is False
    ]
    profile = build_benign_profile(benign_records)
    print(
        f"Benign profile: {len(profile.get('recipients', set()))} recipients, "
        f"{len(profile.get('filepaths', set()))} filepaths",
        file=sys.stderr,
    )

    # 3. Extract features
    def featurize(records):
        X, y, errors = [], [], []
        n_feat = len(FEATURE_NAMES)  # 40 = 11+8+6+6+9 (fraud group = 9, fillers dropped)
        for r in records:
            try:
                fv = extract_features(r, profile)
                assert len(fv) == n_feat, f"got {len(fv)} features for {r.get('id', '?')}"
                X.append(fv)
                y.append(int(r["label"]["is_malicious"]))
            except Exception as e:
                errors.append(f"{r.get('id', '?')}: {e}")
        return np.array(X), np.array(y), errors

    X_train, y_train, err_train = featurize(train_all)
    X_id, y_id, err_id = featurize(test_indist)
    X_ho, y_ho, err_ho = featurize(test_holdout)

    if err_train:
        print(f"Feature extraction errors (train): {err_train[:5]}", file=sys.stderr)
    if err_id:
        print(f"Feature extraction errors (test_indist): {err_id[:5]}", file=sys.stderr)
    if err_ho:
        print(f"Feature extraction errors (test_holdout): {err_ho[:5]}", file=sys.stderr)

    # 4. Train XGBoost (full 40 features)
    clf = xgb.XGBClassifier(
        n_estimators=180,
        max_depth=4,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # Save model
    models_dir = repo / "tier1" / "models"
    models_dir.mkdir(exist_ok=True)
    clf.save_model(str(models_dir / "xgboost_full.json"))

    # 5. Evaluate
    def eval_metrics(clf_m, X, y, name):
        prob = clf_m.predict_proba(X)[:, 1]
        pred = (prob >= 0.5).astype(int)
        auc = (
            roc_auc_score(y, prob) if len(set(y)) > 1 else float("nan")
        )
        f1 = f1_score(y, pred)
        prec = precision_score(y, pred, zero_division=0)
        rec = recall_score(y, pred, zero_division=0)
        det_rate = pred.sum() / len(pred) if len(pred) > 0 else 0
        print(
            f"{name}: AUC={auc:.3f} F1={f1:.3f} Prec={prec:.3f} "
            f"Rec={rec:.3f} DetRate={det_rate:.3f}",
            file=sys.stderr,
        )
        return {
            "AUC": auc,
            "F1": f1,
            "Precision": prec,
            "Recall": rec,
            "DetectionRate": det_rate,
        }

    metrics_id = eval_metrics(clf, X_id, y_id, "test_indist")
    metrics_ho = eval_metrics(clf, X_ho, y_ho, "test_holdout")

    # 6. Ablation: drop local fraud-inspired features (cols 31-39)
    fraud_cols = FEATURE_GROUPS["fraud"]
    X_train_abl = np.delete(X_train, fraud_cols, axis=1)
    X_id_abl = np.delete(X_id, fraud_cols, axis=1)
    X_ho_abl = np.delete(X_ho, fraud_cols, axis=1)

    clf_abl = xgb.XGBClassifier(
        n_estimators=180,
        max_depth=4,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
    )
    clf_abl.fit(X_train_abl, y_train)
    clf_abl.save_model(str(models_dir / "xgboost_ablated.json"))

    metrics_id_abl = eval_metrics(clf_abl, X_id_abl, y_id, "test_indist_ablated")
    metrics_ho_abl = eval_metrics(clf_abl, X_ho_abl, y_ho, "test_holdout_ablated")

    # 7. Delta
    delta_id = {k: metrics_id[k] - metrics_id_abl[k] for k in metrics_id}
    delta_ho = {k: metrics_ho[k] - metrics_ho_abl[k] for k in metrics_ho}

    print("--- Ablation delta (full - ablated) ---", file=sys.stderr)
    for k in delta_id:
        print(f"  test_indist {k}: {delta_id[k]:+.3f}", file=sys.stderr)
    for k in delta_ho:
        print(f"  test_holdout {k}: {delta_ho[k]:+.3f}", file=sys.stderr)

    # 8. Write results
    report = repo / "reports" / "tier1_results.json"
    report.parent.mkdir(exist_ok=True)
    results = {
        "full": {"test_indist": metrics_id, "test_holdout": metrics_ho},
        "ablated": {"test_indist": metrics_id_abl, "test_holdout": metrics_ho_abl},
        "delta": {"test_indist": delta_id, "test_holdout": delta_ho},
        "train_size": len(X_train),
        "train_sources": {
            "real": len(train_real),
            "synth_xgboost_paper": len(train_synth),
            "promptfoo_redteam": len(train_promptfoo),
        },
        "feature_dim": len(FEATURE_NAMES),
        "n_estimators": 180,
        "max_depth": 4,
        "fraud_cols_dropped": fraud_cols,
        "honest_limitations": [
            "test_holdout_family has NO benign records (100% malicious); "
            "DetectionRate is the only meaningful metric; "
            "AUC/F1/Prec/Rec are degenerate",
            "Most real test records are single-turn; fraud-inspired multi-turn "
            "features (cumulative_risk, monotonicity, action_burst, "
            "context_exfil_gap) are 0/degenerate for single-turn records",
            "denied_tool_call_count and failed_tool_call_count are always 0 "
            "(data unavailable in v0)",
            "novelty features depend on benign training profile coverage; "
            "unseen-but-benign files/urls in test will trigger false positive flags",
            "novelty_*_score are exact aliases of their corresponding flags; "
            "they are retained for saved-model compatibility and are not "
            "independent paper features",
            "The paper trains on synthetic-only data; we add synthetic to real "
            "training + promptfoo LLM-generated adversarial inputs (dilution, "
            "scaled to ~3864 across 30 coding-agent/agentic plugins + 4 encoding "
            "strategies) — distribution shift may affect feature importance. "
            "promptfoo is adversarial-only, so it pushes the train class balance "
            "to ~2.45:1 malicious:benign; no scale_pos_weight is applied in Part 1 "
            "(kept consistent across all comparison groups in Part 3).",
            "Local fraud group is 9 features, not the official implementation's "
            "11: three official prior-state signals are absent, a distinct-tool "
            "proxy lives in session, and two local novelty-score columns alias flags",
        ],
    }
    report.write_text(json.dumps(results, indent=2, default=str))
    print(f"Results written to {report}", file=sys.stderr)


if __name__ == "__main__":
    main()
