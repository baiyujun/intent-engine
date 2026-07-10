# Part 5 — Single-Model Dual-Track Assessment + v0.2 Summary

## The Single-Model Question (Part 5)

The user asked: if a single XGBoost can't handle both single-turn and multi-turn, report honestly — but do NOT decide to split models (that's an architecture decision for the human).

### Full picture: Tier-1 alone vs Pipeline (Tier0 ∪ Tier1)

| Track | Split | Tier-1 AUC | Pipeline AUC | Pipeline Recall | Pipeline benign-FP |
|-------|-------|-----------|--------------|-----------------|-------------------|
| Single-turn | test_indist | 0.8420 | **0.9763** | 0.982 | 15% (8/52) |
| Single-turn | aug_holdout | 0.5334 | **0.8667** | 0.917 | 22% (11/49) |
| Multi-turn | record | 0.9348 | **0.9348** | 0.980 | 47% (19/40) |
| Multi-turn | prefix | 0.9049 | — (pipeline is record-level) | — | — |

### Does a single model fail to handle both tracks?

**No — the single-model concern does NOT manifest as a single-vs-multi tradeoff.** Two separate observations:

1. **Tier-1 XGBoost alone** has a real weakness, but it is NOT single-vs-multi:
   - Multi-turn: AUC 0.90 (excellent)
   - Single-turn in-distribution (test_indist): AUC 0.84 (good)
   - Single-turn novel-family (aug_holdout): AUC 0.53 (bad)
   The 0.53 is a **distribution-shift** problem (AdvBench novel family), not a turn-count problem. The model is fine on single-turn *in-distribution* and fine on multi-turn. It fails specifically on *novel-family single-turn*, which needs single-turn **text** features (Tier0's domain), not trajectory features.

2. **The full pipeline** handles both tracks well (0.87 single / 0.93 multi). Tier0's rule engine + vector retrieval catches the single-turn AdvBench attacks that Tier1's trajectory features miss. This is the system working as designed — layers cover each other's gaps.

### The reframing of v0.1's "aug_holdout 0.53"

The v0.1 headline ("aug_holdout AUC ~0.54 near-random, root cause = single-turn vs multi-turn mismatch") was **measuring Tier-1 in isolation**. That was a correct diagnosis of *the Tier-1 layer's* limitation. v0.2's pipeline view reveals the system is healthier — but the credit is **Tier-0's**, not a Tier-0/Tier-1 synergy:

**Pipeline AUC decomposition on aug_holdout (honest, verified):**
| Score source | AUC |
|---|---|
| Tier1-prob on Tier1-invoked records (789/842) | 0.5601 |
| Tier0-verdict ordinal (malicious=0.9/suspicious=0.6/benign=0.1) | **0.8354** |
| Pipeline combined (tier1_prob ∪ crude tier0 map) | 0.8667 |

The pipeline's 0.87 ≈ Tier0's 0.8354. **Tier-0 (rule engine + vector retrieval) is the real single-turn detector** — its 3-way verdict (malicious/suspicious/benign) ranks single-turn AdvBench attacks at AUC 0.8354, even though only 2.1% get a flat "malicious" verdict (the "suspicious" verdict, which escalates to Tier1, does the ranking work). Tier-1's trajectory features add only ~0.03 on single-turn (0.56 vs 0.8354).

This is the genuine, verified picture — not an artifact. The crude 0.9/0.6/0.1 mapping is a legitimate ordinal encoding of Tier0's verdict; the 0.8354 is Tier0's honest ranking quality. I initially read the 0.87 as a clean pipeline probability; the decomposition corrects that to "Tier0 carries single-turn, Tier1 carries multi-turn — complementary by design."

### Honest caveats (not hidden)

- **Pipeline benign false positives are high**: 22% (single-turn aug_holdout) and **47% (multi-turn)**. The pipeline is recall-heavy/conservative (block if Tier0 malicious OR Tier1 prob≥0.5 — the documented union). It catches almost everything (recall 0.92–0.98) but over-flags benign, especially benign multi-turn controls (19/40). This is the real remaining weakness, and it is a *precision* problem, not a single-vs-multi problem.
- **The pipeline AUC's Tier1 component is near-random on single-turn** (0.56). The pipeline does not "fix" Tier1's single-turn weakness — it *bypasses* it via Tier0. A future round should give Tier1 single-turn text features so it contributes on single-turn too.
- **Multi-turn holdout is small** (51 malicious). The 0.93 is robust at the prefix level (357 instances) but the malicious record count is modest.

### Do NOT split the model (Part 5 decision left to the human)

I did not split into separate single-turn / multi-turn sub-models. The data says a split is **not warranted**:
- The pipeline already covers both tracks (0.87 / 0.93).
- The Tier-1 weakness is distribution-shift (novel-family single-turn), which a multi-turn sub-model wouldn't fix anyway.
- The real remaining problem is **benign false positives** (precision), which a split doesn't address — it needs better benign calibration / thresholding, an architecture decision for the human.

The numbers are reported; the split decision is the human's.

## v0.2 Summary

### What v0.2 did
- **Part 0**: Code-reuse principle saved to memory (no hand-written generators; itertools / promptfoo only).
- **Part 1**: Built a structurally-novel multi-turn holdout via promptfoo's real GOAT/Crescendo engine (51 malicious + 40 benign). Discovered GOAT/Crescendo are eval-time providers, not offline generators.
- **Part 2**: Audited single-turn test sources — 0% synthetic in any test split; AgentDojo/InjecAgent/BIPIA nearly absent.
- **Part 3**: Dual-track eval, never merged: single-turn (record) + multi-turn (prefix). Multi-turn AUC 0.90; single-turn aug_holdout Tier1-only 0.53.
- **Part 4**: session_length already exists (index 18); ablation shows negligible marginal effect (~±0.004) — turn-awareness is present but not the lever.
- **Part 5**: Pipeline reframes the 0.53 as a Tier-1-isolation artifact; system AUC 0.87 (single) / 0.93 (multi). Single model handles both; no split warranted; benign-FP is the real gap.

### Numbers (never combined into one)
| | Tier-1 AUC | Tier0-verdict AUC | Pipeline AUC |
|---|---|---|---|
| Single-turn test_indist | 0.8420 | — | 0.9763 |
| Single-turn aug_holdout | 0.5334 | **0.8354** | 0.8667 |
| Multi-turn prefix | 0.9049 | — | — (pipeline is record-level) |
| Multi-turn record | 0.9348 | — | 0.9348 |

(Tier0-verdict AUC on aug_holdout = 0.8354 is the honest backbone; pipeline 0.87 ≈ Tier0 because Tier1 contributes ~0 on single-turn.)

### Next levers (for a future round)
1. **Single-turn text features for Tier-1** (so it doesn't rely on Tier0 for novel-family single-turn).
2. **Benign false-positive reduction** — the multi-turn benign FP (47%) is the real operational gap.
3. **More GOAT multi-turn data** to tighten the 0.90 estimate.
