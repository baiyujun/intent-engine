# Part 2 — Target-Aligned Single-Turn Test Set (rebuilt)

## What was wrong (v0.2 audit confirmed)

The v0.2 single-turn test sets were **off-target** and partly **in-distribution**:

| source | in test | target? | actual content |
|--------|---------|---------|----------------|
| jailbreakbench | 84 (indist) / 0 (holdout used 510 advbench+283 gtfobins) | NO (mostly) | "bomb/anorexia/hate-speech/porn" content-safety jailbreaks |
| advbench | 510 (holdout) | partial | "make a bomb / cyberbully / hack a network" mixed |
| hf_deepset (benign) | 72 (indist) | NO | "What is wonderful?" general QA |
| gtfobins/lolbas | 56+50 (indist) / 283 (holdout) | data-type mismatch | raw shell command strings (`rundll32.exe ...`) |

`normalize_jailbreakbench.py` already carried the caveat `"domain-gap: general content-safety jailbreak, not Agent action-risk; ablation candidate"` — but no filter was ever applied. `test_indist` was 100% same-source-as-train (JBB 61% text identical to train) — an in-distribution split, not a real holdout.

## The Rebuild (`dataset/scripts/build_on_target_testset.py`)

A **filter + partitioner** over existing processed records (no new generation — Part-0 compliant):

1. **Malicious** — keep only target categories/goals:
   - JailbreakBench: `Malware/Hacking`, `Fraud/Deception`, `Privacy`, `Economic harm` (4 cats)
   - AdvBench: goals matching code-exec/privilege/exfiltration keywords, excluding bomb/hate/anorexia/etc.
   - **GTFOBins/LOLBAS raw command strings excluded** (data-type mismatch: shell commands ≠ NL intent)
2. **Benign** — AgentDojo tool-calling tasks (compliant source), NOT in train
3. **True holdout** — disjoint from train by id (leakage check = 0)

## Result

| | count | train-id leak |
|---|-------|---------------|
| on-target malicious | 161 (24 JBB target + 137 AdvBench target) | 0 |
| on-target benign (AgentDojo) | 14 | 0 |
| combined holdout | 175 | 0 |
| JBB DROPPED (off-target cats) | 503 (Harassment/Physical/Sexual/Disinformation/Expert/Govt) | — |
| AdvBench DROPPED (off-target goals) | 373 | — |

## v0.3 Fusion Rule Eval on the On-Target Set (continuous signals, no ordinal AUC)

| set | benign hard-block FP | malicious hard-block recall | malicious review recall |
|-----|---------------------|----------------------------|-------------------------|
| **on_target (175)** | **0.0%** | **58.4%** | 92.5% |
| off_target test_indist (275) | 0.0% | 88.3% | 98.2% |

## The Honest Finding This Exposes

**The off-target test_indist overstated the pipeline's single-turn ability.** On a genuinely target-aligned holdout, malicious **hard-block recall drops from 88.3% → 58.4%** — a 30-point gap hidden by the off-target test set. The v0.2 "pipeline AUC 0.97 on test_indist" was measuring recognition of "bomb/porn/hate-speech" prompts (which Tier0's vector retrieval trivially separates from "what is wonderful?"), NOT recognition of agent-action-risk.

The new fusion rule's red-line fix holds (benign hard-block FP 0% on both), but the single-turn malicious-recall picture is materially worse than v0.2 suggested once the test set actually matches the target scenario. This is the kind of finding that only surfaces when the test set is rebuilt honestly.

## Open Decision (flagged, not auto-resolved)

The on-target benign holdout is only **14** (AgentDojo benign not-in-train is thin; 77 of 91 are in train). Two honest options, NOT decided by me:
- **(A)** Resplit: move ~17 AgentDojo benign from train → holdout (train benign 399→382, imbalance 2.45→2.50:1, negligible). This is a partition, not generation (Part-0 compliant), but it mutates the training set.
- **(B)** Keep n=14 benign and report wide CI (Part 4 bootstrap).

This is flagged for the user. The malicious side (161) is robust; the benign thinness is the constraint.
