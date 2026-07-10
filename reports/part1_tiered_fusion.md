# Part 1 — Tiered Fusion Rule: fixes the multi-turn benign red-line

## The Problem (confirmed from v0.2 audit)

Old `_decide`: `tier0 malicious OR (tier1 invoked AND prob>=0.5) → block`.

When Tier0 returns `benign` but `escalated=True` (fuzzy zone / rule-vs-vector disagreement — common on multi-turn benign because the margin sits near 0), Tier1 is invoked, and Tier1's trajectory features (tool_diversity/action_burst) can't tell "benign multi-step task" from "malicious multi-step attack chain" → Tier1 returns prob≥0.5 → **hard block, ignoring Tier0's benign lean**.

Result on multi-turn benign (n=40): Tier0 alone FP **7.5%**; old union rule FP **40%** (red line).

## The Fix — tiered confidence gating

New `_decide` keys off **Tier0's own verdict**, not just Tier1's prob:

| Tier0 verdict | Tier1 prob | new decision |
|---------------|-----------|--------------|
| malicious | (any) | **block** |
| suspicious | ≥ P_SUSP_BLOCK (0.5) | **block** |
| suspicious | < 0.5 | escalate |
| benign | ≥ P_BENIGN_HARD (0.5) | **defer** (review, NOT auto-block) |
| benign | ≥ P_BENIGN_SOFT (0.4) | escalate |
| benign | < 0.4 | allow |

Key change: **when Tier0 itself leans benign, Tier1's high prob can only DEFER (send to human review), never auto-block.** Only when Tier0 is already suspicious/malicious does Tier1's high prob trigger a hard block.

## Results (preliminary — multi-turn benign has Part-0 caveat: hand-written, untrustworthy)

### MULTI-TURN holdout (n=91: 51 mal + 40 ben) — the on-target signal

| rule | recall | benign hard-FP | TP | FP | FN | TN |
|------|--------|---------------|----|----|----|----|
| OLD union hardblock | 94.1% | **40.0%** | 48 | 16 | 3 | 24 |
| NEW hardblock-only | 82.4% | **2.5%** | 42 | 1 | 9 | 39 |
| NEW (block+defer+escalate flagged) | 94.1% | 47.5%* | 48+6defer | 1+15defer | 3 | 24 |

*The 47.5% "flagged" counts defer as flagged — but defer means **review, not auto-block**. The metric that matters for the red line is **hard-block FP = 2.5%** (down from 40%).

### Honest decomposition of the 21 deferred cases (p_bh=0.5)

- 6 malicious deferred (Tier1 prob 0.76–1.0; Tier0 said benign) → **review catches them** → review-recall = 94.1% (same as old hard-block recall).
- 15 benign deferred → moved from auto-block to review (not blocked).
- Net: 15 benign saved from auto-block; hard-block FP 40% → 2.5%.

### Recall cost (honest)

Hard-block recall dropped 94.1% → 82.4%. But of the 9 no-longer-hard-blocked malicious, **6 are deferred** (review-recall unchanged at 94.1%) and only **3 are escalated/allowed** — and those same 3 were missed by the old rule too (old FN=3). So the new rule loses **zero** review-recall vs old while cutting benign hard-FP 40% → 2.5%.

### SINGLE-TURN (off-target — included for completeness, NOT trusted per Part 2)

| set | rule | recall | benign FP (hard) |
|-----|------|--------|------------------|
| test_indist | OLD | 90.6% | 9.6% |
| test_indist | NEW hardblock | 88.3% | 1.9% |
| aug_holdout | OLD | 65.4% | 12.2% |
| aug_holdout | NEW hardblock | 56.1% | 6.1% |

Single-turn shows the same direction (benign hard-FP drops) but **these test sets are off-target** (通用有害 vs 通用QA, not agent-attack) and partly in-distribution — Part 2 rebuilds them. Do not conclude from these.

### Continuous-signal AUC (no discrete-ordinal encoding — fixes v0.2 method error)

| set | tier0_margin AUC | tier1_prob AUC |
|-----|------------------|----------------|
| multiturn | 0.9127 | 0.9348 |
| test_indist | 0.9821 | 0.9763 |
| aug_holdout | 0.9310 | 0.8880 |

tier0_score = `-vector_margin` (d_ben − d_mal); tier1_score = prob. Both genuine continuous rankings.

## Verdict

**The hypothesis is confirmed on preliminary data**: gating Tier1's hard-block by Tier0's own verdict cuts multi-turn benign hard-FP from 40% → 2.5% (≈ Tier0-alone's 7.5%, actually lower) **with no loss of review-recall**. This is the round's primary deliverable.

Caveats (honest):
- Multi-turn benign is the Part-0-untrustworthy hand-written set — this is preliminary. Part 3 will rebuild benign with AgentDojo; Part 4 will re-verify.
- The fix trades 21 auto-blocks for 21 reviews (15 benign + 6 malicious). Operationally that's a human-review load of 21/91 ≈ 23% — acceptable vs a 40% auto-block of benign, but a real cost.
- p_bh sweep (0.5–0.9) barely changes hard-FP (2.5% throughout) — the gate is doing the work, not the threshold; robust.
