"""Prefix-level incremental evaluation — the paper's core eval (arXiv:2605.01143 §4).

The paper evaluates the detector at the *prefix* level, not the record level:
for each multi-turn interaction, every partial history S1:t (turns 1..t) is
an evaluation instance. Each prefix S1:t is labeled adversarial (y=1) if the
WHOLE interaction ultimately leads to an unsafe execution event (a sensitive
file read co-occurring with external exfiltration, or an unauthorized
privileged execution); benign (y=0) otherwise. This reflects the operational
objective: flag a risky trajectory *before* the harmful action is executed.

This module:
  - emits prefixes from multi-turn records (a t-turn record -> t prefixes)
  - extracts features incrementally per prefix (extract_features on the
    truncated turns; the single-turn degenerate features are genuine here —
    a 1-turn prefix of a privilege-drift interaction SHOULD look mostly benign,
    and the question is whether the model can still flag it)
  - evaluates a trained XGBoost model over the prefixes of a split
  - reports prefix-level AUC / F1 / Precision / Recall / DetectionRate and the
    *early-detection profile*: at which prefix-index the model first flags an
    ultimately-adversarial interaction.

Single-turn records contribute exactly 1 prefix (t=1); multi-turn records
contribute len(turns) prefixes. Only multi-turn adversarial families
(split_exfil / context_laundering / privilege_drift / staged_burst) actually
exercyze the "flag-before-the-harmful-action" property; real single-turn
records are included for completeness but their prefixes are trivial.
"""
from __future__ import annotations

import json
import pathlib
import sys

# standalone import shim
_REPO = pathlib.Path(__file__).resolve().parents[1]
_DS = _REPO / "dataset" / "src"
_ROOT = pathlib.Path(__file__).resolve().parents[1]
for _p in (str(_DS), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    roc_auc_score, f1_score, precision_score, recall_score,
)

from schema import validate_record  # noqa: E402
from tier1.features import (  # noqa: E402
    extract_features, build_benign_profile, FEATURE_NAMES,
)


def load_jsonl(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def prefixes(record):
    """Yield (t, prefix_record) for each partial history S1:t of a record.

    A prefix_record is a shallow copy of `record` with `turns` truncated to the
    first t turns (turn_index 0..t-1). structured_action/label are kept as the
    WHOLE record's — the label is the whole-interaction label (paper: a prefix
    is y=1 if the interaction ultimately leads to an unsafe event). This is the
    faithful label semantics: we want to flag the trajectory before the harm.

    t runs 1..len(turns). (A 1-turn record yields exactly 1 prefix at t=1.)
    """
    turns = record.get("turns", []) or []
    n = len(turns)
    for t in range(1, n + 1):
        pre = dict(record)
        pre["turns"] = turns[:t]
        yield t, pre


def extract_prefix_matrix(records, profile):
    """Return (X, y, prefix_meta) over all prefixes of all records.

    prefix_meta is a list of (record_id, t, y) so we can report the
    early-detection profile.
    """
    X, y, meta = [], [], []
    for r in records:
        y_full = int(r["label"]["is_malicious"])
        rid = r.get("id", "?")
        for t, pre in prefixes(r):
            fv = extract_features(pre, profile)
            assert len(fv) == len(FEATURE_NAMES)
            X.append(fv)
            y.append(y_full)  # prefix label = whole-interaction label
            meta.append((rid, t, y_full))
    return np.array(X), np.array(y), meta


def evaluate_prefixes(model, records, profile, split_name=""):
    """Evaluate `model` at the prefix level over `records`.

    Returns a dict with prefix-level metrics + the early-detection profile:
      - AUC / F1 / Prec / Rec / DetectionRate (prefix level, prob>=0.5)
      - n_prefixes, n_adversarial_prefixes, n_records
      - early_detection: for records whose whole label is adversarial, the
        distribution of the first prefix index at which the model flags it
        (prob >= 0.5). 'never' if never flagged. A model that flags at t=1 on a
        4-turn privilege-drift is early; one that only flags at t=4 is late.
    """
    X, y, meta = extract_prefix_matrix(records, profile)
    prob = model.predict_proba(X)[:, 1]
    pred = (prob >= 0.5).astype(int)

    auc = roc_auc_score(y, prob) if len(set(y)) > 1 else float("nan")
    f1 = f1_score(y, pred, zero_division=0)
    prec = precision_score(y, pred, zero_division=0)
    rec = recall_score(y, pred, zero_division=0)
    det_rate = float(pred.sum()) / len(pred) if len(pred) else 0.0

    # early detection: per adversarial record, first flagged prefix index
    from collections import defaultdict, Counter
    by_rec = defaultdict(list)
    for (rid, t, yfull), p in zip(meta, pred):
        by_rec[rid].append((t, yfull, p))
    first_flag = Counter()
    for rid, seq in by_rec.items():
        yfull = seq[0][1]
        if not yfull:
            continue  # only adversarial records
        flagged = [t for (t, _, p) in seq if p]
        first_flag[flagged[0] if flagged else "never"] += 1

    metrics = {
        "n_records": len(records),
        "n_prefixes": len(X),
        "n_adversarial_prefixes": int(y.sum()),
        "AUC": float(auc) if auc == auc else float("nan"),  # nan guard
        "F1": float(f1),
        "Precision": float(prec),
        "Recall": float(rec),
        "DetectionRate": float(det_rate),
        "early_detection_first_flag_at_prefix": dict(first_flag),
    }
    if split_name:
        print(
            f"prefix[{split_name}]: records={len(records)} prefixes={len(X)} "
            f"(adv={int(y.sum())}) AUC={auc:.3f} F1={f1:.3f} "
            f"Prec={prec:.3f} Rec={rec:.3f} DetRate={det_rate:.3f}",
            file=sys.stderr,
        )
        print(f"  early-flag at prefix t (adv records): {dict(first_flag)}", file=sys.stderr)
    return metrics


def main():
    DATA = _REPO / "dataset"
    repo = _REPO

    # load the trained full model + build benign profile from TRAINING benign
    train = (
        load_jsonl(DATA / "processed/train.jsonl")
        + load_jsonl(DATA / "synthetic/xgboost_paper_derived.jsonl")
        + load_jsonl(DATA / "synthetic/promptfoo_redteam.jsonl")
    )
    benign = [r for r in train if r.get("label", {}).get("is_malicious") is False]
    profile = build_benign_profile(benign)

    model = xgb.XGBClassifier()
    model.load_model(str(repo / "tier1/models/xgboost_full.json"))

    # Prefix-level eval on the multi-turn-rich splits. The real test sets are
    # mostly single-turn (so prefix eval is trivial there); the meaningful
    # prefix test is on the multi-turn synthetic + promptfoo families, where
    # the "flag-before-harm" property actually applies. We eval BOTH:
    #   - real test_indist (prefix-trivial but reported for completeness)
    #   - synthetic xgboost_paper_derived (the multi-turn adversarial families)
    test_indist = load_jsonl(DATA / "processed/test_indist.jsonl")
    test_holdout = load_jsonl(DATA / "processed/test_holdout_family.jsonl")
    synth = load_jsonl(DATA / "synthetic/xgboost_paper_derived.jsonl")

    results = {}
    results["test_indist"] = evaluate_prefixes(model, test_indist, profile, "test_indist")
    results["test_holdout"] = evaluate_prefixes(model, test_holdout, profile, "test_holdout")
    results["synth_xgboost_paper"] = evaluate_prefixes(model, synth, profile, "synth_xgboost_paper")

    out = repo / "reports/tier1_prefix_eval.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"prefix eval written to {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
