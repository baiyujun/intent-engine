"""Part 1: tiered fusion rule — fix the red-line benign-FP.

v0.2 problem: when Tier0 returns `benign` but `escalated=True` (fuzzy/disagreement),
Tier1 is invoked and prob>=0.5 -> hard block, IGNORING Tier0's own benign lean.
On multi-turn benign this caused 47.5% FP (Tier0 alone was only 7.5%).

New rule (tiered confidence gating):
  - Tier0 final_verdict == malicious  -> block (Tier0 itself says bad)
  - Tier0 final_verdict == suspicious AND tier1 prob >= P_SUSP_BLOCK -> block
  - Tier0 final_verdict == benign (regardless of escalated/fuzzy):
      if tier1 prob >= P_BENIGN_HARD   -> defer (NOT hard block; send to review)
      elif tier1 prob >= P_BENIGN_SOFT  -> escalate
      else -> allow
  i.e. when Tier0 itself leans benign, Tier1's high prob can only DEFER, not block.

All AUC computed on CONTINUOUS signals only:
  - Tier0 score = -vector_margin  (d_ben - d_mal; higher = more malicious)
  - Tier1 score = tier1 prob
  - Pipeline combined score = gated combination (see compute_combined_score)

Usage: python tier1/part1_tiered_fusion.py
"""
import os
import sys
import pathlib
import json

os.environ.setdefault("TIER0_FORCE_SKLEARN", "1")
_REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPOSITORY / "dataset" / "src"))
sys.path.insert(0, str(_REPOSITORY))

import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402
from sklearn.metrics import roc_auc_score, f1_score, precision_score, recall_score  # noqa: E402

from pipeline import Pipeline  # noqa: E402
from tier0.fusion import judge as t0_judge  # noqa: E402
from tier1.features import extract_features, build_benign_profile  # noqa: E402

DATA = _REPOSITORY / "dataset"
REPO = _REPOSITORY


def load_jsonl(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


# ── new tiered fusion rule ───────────────────────────────────────────────────
def tiered_decide(t0_verdict, t0_margin, prob,
                 p_benign_hard=0.5, p_benign_soft=0.4, p_susp_block=0.5):
    """Return one of block / defer / escalate / allow.
    t0_margin = d_mal - d_ben (positive = benign lean).
    prob = Tier1 malicious probability (None if not invoked)."""
    if t0_verdict == "malicious":
        return "block"
    if t0_verdict == "suspicious":
        if prob is not None and prob >= p_susp_block:
            return "block"
        return "escalate"
    # t0_verdict == "benign"
    if prob is None:
        return "allow"
    if prob >= p_benign_hard:
        return "defer"  # Tier1 says bad but Tier0 leans benign -> review, not block
    if prob >= p_benign_soft:
        return "escalate"
    return "allow"


def decision_to_pred(d):
    """block -> flagged(1). defer -> flagged(1) for recall, BUT separate track
    so we can report hard-block-FP vs defer-FP distinctly. escalate -> flagged(1)."""
    return 1 if d in ("block", "escalate", "defer") else 0


def decision_to_hardblock(d):
    """Only hard block counts as 'blocked' for the red-line FP metric."""
    return 1 if d == "block" else 0


def evaluate(records, profile, clf, label, rule_kwargs):
    """Run Tier0+Tier1 on records, apply BOTH old and new rule, report comparison."""
    rows = []
    for r in records:
        text = " ".join(t.get("raw_text", "") for t in r.get("turns", []))
        t0 = t0_judge(text, models_dir="tier0/models", text_only=True)
        t1_invoked = bool(t0.escalated or t0.final_verdict in ("suspicious", "malicious"))
        prob = None
        if t1_invoked:
            fv = extract_features(r, profile)
            prob = float(clf.predict_proba([fv])[0, 1])
        is_mal = int(r["label"]["is_malicious"])
        rows.append({
            "y": is_mal, "t0v": t0.final_verdict, "t0m": t0.vector_margin,
            "prob": prob, "t1inv": t1_invoked,
        })

    y = np.array([r["y"] for r in rows])
    # OLD rule (union hard block): block if t0 malicious OR t1 prob>=0.5
    old_pred = np.array([
        1 if (r["t0v"] == "malicious" or (r["prob"] is not None and r["prob"] >= 0.5))
        else 0 for r in rows
    ])
    # NEW rule
    new_decisions = [tiered_decide(r["t0v"], r["t0m"], r["prob"], **rule_kwargs) for r in rows]
    new_flag = np.array([decision_to_pred(d) for d in new_decisions])
    new_hard = np.array([decision_to_hardblock(d) for d in new_decisions])
    n_defer = sum(1 for d in new_decisions if d == "defer")

    n = len(y); n_mal = int(y.sum()); n_ben = n - n_mal

    def rates(pred):
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        det = tp / n_mal if n_mal else 0  # recall on malicious
        fp_r = fp / n_ben if n_ben else 0  # benign FP
        return tp, fp, fn, tn, det, fp_r

    ot, of, ofn, otn, odet, ofp = rates(old_pred)
    nt, nf, nfn, ntn, ndet, nfp = rates(new_flag)
    ht, hf, hfn, htn, hdet, hfp = rates(new_hard)

    print(f"\n{'='*74}", file=sys.stderr)
    print(f"  {label}  (n={n} mal={n_mal} ben={n_ben})  rule={rule_kwargs}", file=sys.stderr)
    print(f"{'='*74}", file=sys.stderr)
    print(f"  {'rule':<22} {'recall':>7} {'benignFP':>9} {'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}", file=sys.stderr)
    print(f"  {'OLD union hardblock':<22} {odet:>6.1%} {ofp:>8.1%}  {ot:>4}{of:>4}{ofn:>4}{otn:>4}", file=sys.stderr)
    print(f"  {'NEW (block+defer+esc)':<22} {ndet:>6.1%} {nfp:>8.1%}  {nt:>4}{nf:>4}{nfn:>4}{ntn:>4}", file=sys.stderr)
    print(f"  {'NEW hardblock only':<22} {hdet:>6.1%} {hfp:>8.1%}  {ht:>4}{hf:>4}{hfn:>4}{htn:>4}", file=sys.stderr)
    print(f"  ({n_defer} deferred to review under new rule)", file=sys.stderr)

    # continuous-signal AUCs
    t0_score = -np.array([r["t0m"] for r in rows])  # higher = more malicious
    t1_scores = [r["prob"] if r["prob"] is not None else 0.0 for r in rows]
    aucs = {}
    for nm, sc in [("tier0_margin", t0_score), ("tier1_prob", np.array(t1_scores))]:
        aucs[nm] = float(roc_auc_score(y, sc)) if len(set(y)) > 1 else float("nan")
    print(f"  continuous AUC: tier0_margin={aucs['tier0_margin']:.4f}  tier1_prob={aucs['tier1_prob']:.4f}", file=sys.stderr)

    return {
        "n": n, "n_mal": n_mal, "n_ben": n_ben,
        "old": {"recall": odet, "benign_fp": ofp, "tp": ot, "fp": of, "fn": ofn, "tn": otn},
        "new_flag": {"recall": ndet, "benign_fp": nfp, "tp": nt, "fp": nf, "fn": nfn, "tn": ntn, "n_defer": n_defer},
        "new_hard": {"recall": hdet, "benign_fp": hfp, "tp": ht, "fp": hf, "fn": hfn, "tn": htn},
        "auc_continuous": aucs,
        "rule_kwargs": rule_kwargs,
    }


def main():
    train = (load_jsonl(DATA / "processed" / "train.jsonl")
             + load_jsonl(DATA / "synthetic" / "xgboost_paper_derived.jsonl")
             + load_jsonl(DATA / "synthetic" / "promptfoo_redteam.jsonl"))
    profile = build_benign_profile([r for r in train if not r["label"]["is_malicious"]])
    clf = xgb.XGBClassifier()
    clf.load_model(str(REPO / "tier1" / "models" / "xgboost_full.json"))

    # multi-turn holdout (benign has Part-0 caveat — preliminary only)
    mt_mal = load_jsonl(DATA / "processed" / "test_holdout_multiturn.jsonl")
    mt_ben = load_jsonl(DATA / "processed" / "test_holdout_multiturn_benign.jsonl")
    mt_all = mt_mal + mt_ben
    # single-turn (off-target, but part of the comparison for completeness)
    test_indist = load_jsonl(DATA / "processed" / "test_indist.jsonl")
    test_holdout = load_jsonl(DATA / "processed" / "test_holdout_family.jsonl")
    val = load_jsonl(DATA / "processed" / "val.jsonl")
    val_benign = [r for r in val if not r["label"]["is_malicious"]]
    aug = test_holdout + val_benign

    print("PART 1: tiered fusion rule vs old union hardblock", file=sys.stderr)
    print("All AUC = continuous signals (tier0_margin, tier1_prob).", file=sys.stderr)
    print("PART-0 CAVEAT: mt benign = v0.2 hand-written, marked untrustworthy —", file=sys.stderr)
    print("preliminary only, NOT a final conclusion.", file=sys.stderr)

    # default rule params (gated by Tier0 verdict)
    RK = dict(p_benign_hard=0.5, p_benign_soft=0.4, p_susp_block=0.5)

    out = {}
    out["multiturn"] = evaluate(mt_all, profile, clf, "MULTI-TURN holdout", RK)
    out["test_indist"] = evaluate(test_indist, profile, clf, "SINGLE test_indist (off-target)", RK)
    out["aug_holdout"] = evaluate(aug, profile, clf, "SINGLE aug_holdout (off-target)", RK)

    # ── sweep: does raising p_benign_hard (defer threshold) trade recall for FP? ──
    print(f"\n{'='*74}\n  SWEEP p_benign_hard (defer threshold) on MULTI-TURN\n{'='*74}", file=sys.stderr)
    print(f"  {'p_bh':<6}{'recall':>8}{'benignFP':>10}{'hardFP':>8}{'n_defer':>9}", file=sys.stderr)
    sweep = []
    for pbh in [0.5, 0.55, 0.6, 0.7, 0.8, 0.9]:
        rk = dict(RK, p_benign_hard=pbh)
        r = evaluate(mt_all, profile, clf, f"  sweep pbh={pbh}", rk)
        sweep.append({"p_benign_hard": pbh,
                      "recall": r["new_flag"]["recall"], "benign_fp": r["new_flag"]["benign_fp"],
                      "hard_fp": r["new_hard"]["benign_fp"], "n_defer": r["new_flag"]["n_defer"]})
        print(f"  {pbh:<6}{r['new_flag']['recall']:>7.1%}{r['new_flag']['benign_fp']:>9.1%}"
              f"{r['new_hard']['benign_fp']:>8.1%}{r['new_flag']['n_defer']:>9}", file=sys.stderr)
    out["sweep"] = sweep

    outpath = REPO / "reports" / "part1_tiered_fusion.json"
    outpath.parent.mkdir(exist_ok=True)
    outpath.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nPart 1 written to {outpath}", file=sys.stderr)


if __name__ == "__main__":
    main()
