# Part 2 — Single-Turn Test Set Source Composition Audit

## Key Finding: 0% Synthetic Data in Any Test Set

All three processed splits (`train`, `val`, `test_indist`, `test_holdout_family`) contain **0% synthetic data**. The synth data (`xgboost_paper_derived.jsonl` and `promptfoo_redteam.jsonl`) lives in `synthetic/` and is loaded separately by `train.py`.

**This means the single-track eval is eval-integrity clean.** The root problem is not synth leakage into test — it's that multi-turn synth training features don't generalize to single-turn public test data.

## test_indist (n=275)

| Source | Count | % |
|--------|-------|---|
| JailbreakBench (Chao et al. 2024) | 84 | 30.5% |
| HuggingFace deepset (public HF) | 72 | 26.2% |
| GTFOBins (public repo) | 56 | 20.4% |
| LOLBAS (Microsoft public repo) | 50 | 18.2% |
| AgentDojo (Ruan et al. 2024) | 10 | 3.6% |
| Near-duplicate pairs | 2 | 0.7% |
| ClawSentry rule patterns | 1 | 0.4% |

**User-specific datasets:**
- AgentDojo: 10 (3.6%)
- InjecAgent: 0 (0%)
- BIPIA: 0 (0%)

**Turn-count:** {1: 275} — **100% single-turn**

## test_holdout_family (n=793)

| Source | Count | % |
|--------|-------|---|
| AdvBench (Zou et al. 2023) | 510 | 64.3% |
| GTFOBins (public repo) | 283 | 35.7% |

**User-specific datasets:** AgentDojo=0, InjecAgent=0, BIPIA=0

**Turn-count:** {1: 793} — **100% single-turn**

## train (n=2,149)

| Source | Count | % |
|--------|-------|---|
| JailbreakBench | 660 | 30.7% |
| HuggingFace deepset | 509 | 23.7% |
| GTFOBins | 420 | 19.5% |
| LOLBAS | 400 | 18.6% |
| AgentDojo | 111 | 5.2% |
| ClawSentry rules | 20 | 0.9% |
| InjecAgent | 17 | 0.8% |
| Near-dup pairs | 12 | 0.6% |

**Note:** InjecAgent has 17 records that are 2-turn (the only multi-turn records in the real-data splits). BIPIA never appears in the dataset at all.

## Honest Risk Assessment

### Risk 1: Single-turn eval may not reflect real agent threat
The test sets are 100% single-turn natural-language attack prompts (from jailbreak/safety benchmarks). Real agent attacks are often multi-turn (Crescendo, GOAT). The single-turn metric measures a DIFFERENT capability than what matters for real agent guardrails.

### Risk 2: Holdout family composition is narrow
test_holdout = 64% AdvBench + 36% GTFOBins. AdvBench is a classic jailbreak benchmark (short adversarial prompts). GTFOBins is a privesc command reference. Both are well-studied. The holdout "novel family" claim is valid for the `advbench`/`gtfobins` families being disjoint from train, but the attack STYLE (single-turn, explicit adversarial) is the same.

### Risk 3: No multi-turn holdout exists yet
This is the gap Part 1 of this round aims to fill.

### Risk 4: AgentDojo/InjecAgent/BIPIA are nearly absent
AgentDojo (3.6% of test_indist, 0% of holdout) and InjecAgent (0% of test, 0.8% of train) are the most agent-relevant datasets, but they barely appear. BIPIA is entirely absent. The test sets are dominated by generic safety benchmarks (JailbreakBench, AdvBench) rather than agent-specific attack scenarios.

## What This Means for Part 3 (Dual-Track Eval)

- **Single-track**: Uses the existing test sets (clean, 100% public, 100% single-turn). Metric is honest but measures a different scenario than multi-turn guardrails.
- **Multi-track**: Will use the new promptfoo-generated holdout (Part 1). This measures actual multi-turn attack detection, which is the operationally relevant metric for agent guardrails.
- **NEVER merge** these into a single number — they answer different questions.
