"""Part 4 — v0.3 final dual-track re-eval (CONSERVATIVE, per v0.3 audit).

Per the v0.3 audit decision: the 40 hand-written multi-turn benign are RETIRED
(shortcut-checkup: audit/security lexical gap 1.15 → retired, not used in any eval).
So this reports:
  - MULTI-TURN: malicious SIDE ONLY (51 records, prefix + record level). No benign
    FP metric (no trustworthy benign). Continuous-signal AUC + bootstrap CI.
  - SINGLE-TURN: on-target holdout (161 mal + 31 ben) — both tracks, bootstrap CI
    on the benign-thin side. Plus off-target test_indist for the honest contrast.
  - Continuous signals only (tier0_margin / tier1_prob). NO discrete-ordinal AUC.
  - All handcrafted_untrusted-derived numbers excluded.

Every number from on-target single-turn benign (n=31, incl. 17 moved from train)
carries a bootstrap CI. The v0.3 fusion rule (Part 1) is the active pipeline._decide.
"""
import os
import sys
import pathlib
import json

os.environ.setdefault("TIER0_FORCE_SKLEARN", "1")
_REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "dataset" / "src"))
sys.path.insert(0, str(_REPO))

import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402
from scipy.stats import beta  # noqa: E402

from tier0.fusion import judge as t0_judge  # noqa: E402
from tier1.features import extract_features, build_benign_profile, FEATURE_NAMES  # noqa: E402
from tier1.prefix_eval import prefixes  # noqa: E402

DATA = _REPO / "dataset"
P = DATA / "processed"
S = DATA / "synthetic"


def load(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def bootstrap_auc(probs, y, n_boot=5000, seed=42):
    rng = np.random.RandomState(seed)
    n = len(y)
    aucs = []
    for _ in range(n_boot):
        idx = rng.randint(0, n, n)
        ys = y[idx]
        if len(set(ys)) < 2:
            continue
        aucs.append(roc_auc_score(ys, probs[idx]))
    a = np.array(aucs)
    pt = roc_auc_score(y, probs)
    return pt, a.mean(), np.percentile(a, 2.5), np.percentile(a, 97.5)


def binom_ci(k, n):
    if n == 0:
        return (float("nan"), float("nan"))
    lo = beta.ppf(0.025, k, n - k + 1) if k > 0 else 0.0
    hi = beta.ppf(0.975, k + 1, n - k) if k < n else 1.0
    return (lo, hi)


def main():
    train = load(P / "train.jsonl") + load(S / "xgboost_paper_derived.jsonl") + load(S / "promptfoo_redteam.jsonl")
    profile = build_benign_profile([r for r in train if not r["label"]["is_malicious"]])
    clf = xgb.XGBClassifier()
    clf.load_model(str(_REPO / "tier1" / "models" / "xgboost_full.json"))

    out = {"handcrafted_untrusted_note": "40 multi-turn benign RETIRED (audit/security lexical gap 1.15). "
          "Multi-turn = malicious side only. Single-turn benign (n=31) bootstrap-CI'd."}

    # ════════════════════════════════════════════════════════════════════
    # TRACK 2 — MULTI-TURN, MALICIOUS SIDE ONLY (no benign: retired)
    # ════════════════════════════════════════════════════════════════════
    print("=" * 70, file=sys.stderr)
    print("TRACK 2 — MULTI-TURN (malicious side only; benign retired)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    mt_mal = load(P / "test_holdout_multiturn.jsonl")
    print(f"  multi-turn malicious: {len(mt_mal)} records", file=sys.stderr)

    # Tier1 prob on prefixes (continuous)
    pf_prob, pf_y = [], []
    for r in mt_mal:
        yf = int(r["label"]["is_malicious"])
        for t, pre in prefixes(r):
            pf_prob.append(float(clf.predict_proba([extract_features(pre, profile)])[0, 1]))
            pf_y.append(yf)
    pf_prob, pf_y = np.array(pf_prob), np.array(pf_y)
    # malicious-only AUC is degenerate (all y=1) — instead report DETECTION: prob distribution
    print(f"  prefixes: {len(pf_y)} (all malicious — AUC undefined, report detection prob stats)", file=sys.stderr)
    print(f"    Tier1 prob: mean={pf_prob.mean():.3f} median={np.median(pf_prob):.3f} "
          f"%>=0.5={100*np.mean(pf_prob>=0.5):.1f}% %>=0.4={100*np.mean(pf_prob>=0.4):.1f}%", file=sys.stderr)
    out["track2_multiturn"] = {
        "note": "benign retired (handcrafted_untrusted); malicious side only",
        "n_malicious_records": len(mt_mal),
        "n_prefixes": int(len(pf_y)),
        "tier1_prob_mean": float(pf_prob.mean()),
        "tier1_prob_median": float(np.median(pf_prob)),
        "pct_prefixes_prob_ge_0.5": float(np.mean(pf_prob >= 0.5)),
        "pct_prefixes_prob_ge_0.4": float(np.mean(pf_prob >= 0.4)),
    }
    # Tier0 margin on malicious records (continuous) — distribution
    t0_mal = [-t0_judge(" ".join(t.get("raw_text", "") for t in r.get("turns", [])),
                        models_dir="tier0/models", text_only=True).vector_margin for r in mt_mal]
    t0_mal = np.array(t0_mal)
    print(f"    Tier0 margin (−=malicious): mean={t0_mal.mean():.3f} %<0(mal-leaning)={100*np.mean(t0_mal<0):.1f}%",
          file=sys.stderr)
    out["track2_multiturn"]["tier0_margin_mean"] = float(t0_mal.mean())
    out["track2_multiturn"]["pct_tier0_mal_leaning"] = float(np.mean(t0_mal < 0))

    # ════════════════════════════════════════════════════════════════════
    # TRACK 1 — SINGLE-TURN, on-target holdout (161 mal + 31 ben) + off-target contrast
    # ════════════════════════════════════════════════════════════════════
    print("=" * 70, file=sys.stderr)
    print("TRACK 1 — SINGLE-TURN (on-target holdout + off-target contrast)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    def single_eval(name, recs):
        n_mal = sum(1 for r in recs if r["label"]["is_malicious"])
        n_ben = len(recs) - n_mal
        # continuous: tier1 prob + tier0 margin
        t1p, t0m, y = [], [], []
        for r in recs:
            fv = extract_features(r, profile)
            t1p.append(float(clf.predict_proba([fv])[0, 1]))
            text = " ".join(t.get("raw_text", "") for t in r.get("turns", []))
            t0m.append(-t0_judge(text, models_dir="tier0/models", text_only=True).vector_margin)
            y.append(int(r["label"]["is_malicious"]))
        t1p, t0m, y = np.array(t1p), np.array(t0m), np.array(y)
        # v0.3 pipeline decision (gating rule) — hard-block recall + benign hard-block FP
        from pipeline import Pipeline
        pipe = Pipeline()
        blk_mal = blk_ben = 0
        for r in recs:
            d = pipe.run(r)["final_decision"]
            if d == "block":
                if r["label"]["is_malicious"]:
                    blk_mal += 1
                else:
                    blk_ben += 1
        # AUC + bootstrap CI (continuous)
        if len(set(y)) > 1:
            t1_pt, _, t1_lo, t1_hi = bootstrap_auc(t1p, y)
            t0_pt, _, t0_lo, t0_hi = bootstrap_auc(t0m, y)
        else:
            t1_pt = t0_pt = float("nan"); t1_lo = t1_hi = t0_lo = t0_hi = float("nan")
        hb_recall = blk_mal / n_mal if n_mal else 0
        hb_fp = blk_ben / n_ben if n_ben else 0
        hb_fp_ci = binom_ci(blk_ben, n_ben) if n_ben else (float("nan"), float("nan"))
        print(f"  [{name}] n={len(recs)} mal={n_mal} ben={n_ben}", file=sys.stderr)
        print(f"    tier1_prob AUC={t1_pt:.4f} CI[{t1_lo:.4f},{t1_hi:.4f}]", file=sys.stderr)
        print(f"    tier0_margin AUC={t0_pt:.4f} CI[{t0_lo:.4f},{t0_hi:.4f}]", file=sys.stderr)
        print(f"    hard-block recall={hb_recall:.1%} | benign hard-FP={hb_fp:.1%} CI[{hb_fp_ci[0]:.3f},{hb_fp_ci[1]:.3f}]",
              file=sys.stderr)
        return {"n": len(recs), "n_mal": n_mal, "n_ben": n_ben,
                "tier1_auc": t1_pt, "tier1_auc_ci": [t1_lo, t1_hi],
                "tier0_auc": t0_pt, "tier0_auc_ci": [t0_lo, t0_hi],
                "hardblock_recall": hb_recall, "benign_hard_fp": hb_fp,
                "benign_hard_fp_ci": list(hb_fp_ci)}

    out["track1_on_target"] = single_eval("on_target (161mal+31ben)", load(P / "test_on_target.jsonl"))
    out["track1_off_target_test_indist"] = single_eval("off_target test_indist (in-dist, contrast)",
                                                        load(P / "test_indist.jsonl"))
    out["track1_off_target_aug_holdout"] = single_eval("off_target aug_holdout (contrast)",
                                                       load(P / "test_holdout_family.jsonl") +
                                                       [r for r in load(P / "val.jsonl") if not r["label"]["is_malicious"]])

    # honest contrast summary
    ot = out["track1_on_target"]; oft = out["track1_off_target_test_indist"]
    print("=" * 70, file=sys.stderr)
    print("HONEST CONTRAST: on-target vs off-target (single-turn)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(f"  hard-block recall: on-target {ot['hardblock_recall']:.1%} vs off-target test_indist {oft['hardblock_recall']:.1%}",
          file=sys.stderr)
    print(f"  tier1 AUC: on-target {ot['tier1_auc']:.4f} vs off-target {oft['tier1_auc']:.4f}", file=sys.stderr)
    print(f"  => off-target overstated recall by {oft['hardblock_recall']-ot['hardblock_recall']:.1%} (absolute)",
          file=sys.stderr)

    outpath = _REPO / "reports" / "part4_final_dualtrack.json"
    outpath.write_text(json.dumps(out, indent=2, default=str))
    print(f"\nPart 4 written to {outpath}", file=sys.stderr)


if __name__ == "__main__":
    main()
