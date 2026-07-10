# Part 3 — Dual-Track Evaluation (Single vs Multi, NEVER Merged)

## The Core Result

The two tracks are evaluated **separately** and never combined into one metric. They answer different questions.

### TRACK 1 — SINGLE-TURN (record level, public datasets)

| Set | n | AUC | F1 | Prec | Rec | TP | FP | TN | FN |
|-----|---|-----|----|------|-----|----|----|----|----|
| test_indist | 275 | **0.8420** | 0.8913 | 0.8650 | 0.9193 | 205 | 32 | 20 | 18 |
| aug_holdout | 842 | **0.5334** | 0.7804 | 0.9477 | 0.6633 | 526 | 29 | 20 | 267 |

- test_indist (in-distribution, shares family/shape with train): AUC 0.84 — good.
- aug_holdout (AdvBench+GTFOBins novel family, 100% single-turn): AUC 0.53 — **near-random**, the v0.1 problem, unchanged.

### TRACK 2 — MULTI-TURN (prefix level, promptfoo GOAT/Crescendo holdout)

| Set | n | AUC | F1 | Prec | Rec | TP | FP | TN | FN |
|-----|---|-----|----|------|-----|----|----|----|----|
| **prefix level** | 357 | **0.9049** | 0.7927 | 0.6794 | 0.9512 | 195 | 92 | 60 | 10 |
| record level (ref) | 91 | **0.9348** | 0.8348 | 0.7500 | 0.9412 | 48 | 16 | 24 | 3 |

- 357 prefixes (205 malicious + 152 benign), session_length varies {1,2,3,4,5,6,7,8,9,10} across prefixes.
- **prefix AUC 0.9049** — the model flags adversarial trajectories at the prefix level (before the full conversation), the paper's "flag-before-harm" objective.

## The Insight

| | Single-turn aug_holdout | Multi-turn holdout |
|---|---|---|
| AUC | 0.5334 | 0.9049 (prefix) / 0.9348 (record) |
| session_length | constant 1.0 (degenerate) | varies 1→10 (active) |
| tool_diversity_score | constant 1.0 (degenerate) | varies (active) |
| action_burst_score | ~0 (degenerate) | varies (active) |
| risk_delta | 0.0 (degenerate) | varies (active) |

**The v0.1 root cause is confirmed and resolved in interpretation, not in the single-turn number.** The model's multi-turn features were never "bad" — they were **degenerate on single-turn data** (constant/zero). On multi-turn data they work excellently (AUC 0.90). The single-turn aug_holdout AUC 0.53 measures a *different capability* (detecting single-turn AdvBench jailbreaks) and is near-random because the model was trained on multi-turn trajectory features.

**These two numbers must never be averaged or combined.** The single-turn 0.53 and multi-turn 0.90 are both honest, both real, and describe different operational scenarios.

## Honest Limitations

- **Small multi-turn n**: 51 malicious records (vs 793 single-turn). The 0.90 AUC is robust at the prefix level (357 instances) but the malicious set is small. More GOAT data would tighten the estimate.
- **High false positives at prefix level**: 92 FP / 152 benign prefixes. The model over-flags benign multi-turn controls at early prefixes (t=1 looks like a normal request but the whole conversation is benign). Precision 0.68 reflects this — recall (0.95) is prioritized, appropriate for a guardrail.
- **aug_holdout still 0.53**: This round did NOT fix the single-turn novel-family problem (that needs single-turn text features, a separate effort). It correctly *separated* it from the multi-turn capability.
