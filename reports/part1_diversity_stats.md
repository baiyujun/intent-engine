# Part 1 — Data Diversity Root Cause Fix: Statistics Summary

## Changes

### Step 1: XGBoost-derived synth vocab expansion (`synth/xgboost_derived.py`)

**Root cause**: `_mixed_radix()` iterated `reversed(bases)`, making the first-listed base the **slowest-advancing** (most-significant) digit. With N=800 and the resource base listed first, only index 0 (`/etc/shadow`) was ever selected — `/etc/shadow` appeared in ~75% of malicious records and only 4 unique exfiltration endpoints appeared.

**Fix**: Changed `_mixed_radix` to iterate `bases` in order (first base = fastest-advancing). Also reordered all generator base lists so resource/endpoint dimensions advance fastest.

**Pool expansions**:
| Pool | Before | After |
|------|--------|-------|
| SENSITIVE_FILES | 10 | 55 |
| EXTERNAL_ENDPOINTS | 6 | 30 |
| BENIGN_FILES | 8 | 30 |
| BENIGN_DIRS | 4 | 10 |
| SHELL_CMDS | 6 | 26 (incl. GTFOBins/LOLBAS) |
| BENIGN_URLS | 4 | 14 |
| BENIGN_END_PHRASING | 10 | 26 (4 summarize + 22 non-summarize) |
| All phrasing pools | 3-6 | 8-14 |

### Step 2: Promptfoo redteam scaling

**Before**: 6 plugins × 40 tests = 240 samples
**After**: 30 plugins × 35 tests + 4 encoding strategies = **3864 samples**

Plugins added: all 13 coding-agent:* plugins, agentic:memory-poisoning, excessive-agency, indirect-prompt-injection, shell-injection, data-exfil, rag-document-exfiltration, tool-discovery, bola, bfla, hijacking, system-prompt-override, ssrf, sql-injection.

Strategies added: base64, leetspeak, prompt-injection, crescendo.

### Step 3: Shortcut-word audit

| Check | Result | Gap |
|-------|--------|-----|
| Any word gap > 0.80 | **None found** | — |
| "summarize" (previously 80.6%→4.0% benign) | 3.6% ben, 0.7% mal | 0.029 |
| "show" (highest-gap word) | 89.0% ben, 27.4% mal | 0.615 |
| "send" | 0.1% ben, 36.8% mal | 0.366 |
| "read" | 89.0% ben, 36.8% mal | 0.522 |
| base64_chunk(30+) | 0.0% ben, 6.2% mal | 0.062 |
| leetspeak(8+ alnum) | 0.0% ben, 2.7% mal | 0.027 |

**Conclusion**: No near-perfect single-feature separators remain. Encoding strategies (base64/leetspeak) appear in only 6.2%/2.7% of malicious records — they add genuine adversarial diversity without becoming shortcuts.

## Training Data Composition

| Source | Count | Malicious | Benign |
|--------|-------|-----------|--------|
| Real (processed/train.jsonl) | 2,149 | 1,750 | 399 |
| Synth (xgboost_paper_derived.jsonl) | 6,400 | 3,200 | 3,200 |
| Promptfoo (promptfoo_redteam.jsonl) | 3,864 | 3,864 | 0 |
| **Total** | **12,413** | **8,814** | **3,599** |

**Class balance**: 71.0% malicious, 29.0% benign → **2.45:1** imbalance.
(Promptfoo is adversarial-only by design. No `scale_pos_weight` applied in Part 1 — kept consistent across all Part 3 comparison groups.)

## Attack Family Diversity (promptfoo)

29 distinct families across 30 plugins. Each base plugin contributes 175 records (35 base × 5 variant groups from strategies).

## Known Limitation

The 2.45:1 class imbalance is a documented side effect of adding promptfoo (all-malicious) to the pool. This is acceptable for the Part 3 three-group comparison (all groups share the same imbalance), but future iterations should consider (a) generating benign LLM data to balance, or (b) setting `scale_pos_weight` in XGBoost.
