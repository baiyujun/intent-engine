# Part 1 — Tiered Fusion Rule: fixes the multi-turn benign red-line

> **CORRECTION (51-record relabel, 2026-07-14):** on identical current code, the
> old labels give tiered hard-block FP **1/40 = 2.5%**; the reviewed 48/3 labels give
> **3/43 = 7.0%**. Review recall remains directionally unchanged
> (**50/51 = 98.04% -> 47/48 = 97.92%**), so the gating direction survives, but
> the 2.5% point estimate and the tables below are not current. Evidence:
> `reports/relabel51_{baseline_,}part1_tiered_fusion.json` and
> `reports/multiturn_relabel_rerun_20260714.md`.

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

### Caveat (specific, per v0.3 audit — NOT just "non-production-representative")

This caveat must travel with the "40%→2.5%" number wherever it is cited.

**修复方向可信，具体数值不可信。** 需要分两层看：

1. **gating 逻辑本身（Tier0 判良性时不让 Tier1 直接硬拦截）这个修复方向成立**——这是架构/逻辑层面的改动，不依赖具体数据的词面分布。无论用什么良性数据，"Tier0 已判 benign 时 Tier1 高分只能 defer 不能 block"这个 gating 都是合理的：它让最可能误拦良性的一类情况（Tier0 benign + Tier1 高分）从自动拦截降级为复核，逻辑上必然降低良性硬拦，且不丢 review-recall。这部分结论是数据无关的、可信的。

2. **但"40%→2.5%"这个具体绝对数值很可能被这批数据的词面指纹抬高**。这次验证用的 40 条良性是 v0.2 手写 archetype 数据，捷径体检发现它们带 `audit/security/compliance` 等近完美区分词（gap 1.15，mal 0% ben 92%）。这些词面指纹让 Tier0 更容易把 40 条判成 benign、Tier1 也更容易区分——**2.5% 这个绝对值偏乐观，不是真实数据上的量化效果**。在真实生产数据（无这些词面指纹）上，hard-FP 的实际降幅可能更小。

**所以：** 报告 "gating 逻辑修复方向成立"（可信）+ 报告 "2.5% 是手写数据上的乐观估计，真实降幅待合规数据验证"（数值不可单独当结论）。这和 Part 4 多轮良性指标共享同一个"handcrafted_untrusted 数据"局限——但 Part 4 已按审计决定放弃多轮良性侧，故 Part 1 的数值局限在此记录、不进 Part 4 结论。

Caveats (honest):
- Multi-turn benign is the Part-0-untrustworthy hand-written set — preliminary, and per the v0.3 shortcut-checkup carries `audit/security` lexical fingerprints (gap 1.15). The 2.5% number is optimistic; the gating *direction* is sound but the *magnitude* is not validated on real data.
- The fix trades 21 auto-blocks for 21 reviews (15 benign + 6 malicious). Operationally that's a human-review load of 21/91 ≈ 23% — acceptable vs a 40% auto-block of benign, but a real cost.
- p_bh sweep (0.5–0.9) barely changes hard-FP (2.5% throughout) — the gate is doing the work, not the threshold; robust.
