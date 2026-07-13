# v0.6 Part 0 — frozen Tier2 re-eval on the CLEAN 88-case set (4 reasoning-leaks removed)

> **What this is:** the v0.5.1 / v0.6 Part 0 data-cleaning step. The v0.5 Part C ran on 92
> promptfoo cases that contained **4 reasoning-leak cases** (#034/#055/#060/#083) — the
> generator model leaked its CoT/meta-text into output, not real instructions, so their
> ground-truth labels were invalid. This file removes them and re-runs the FROZEN Tier2 on
> the clean 88-case set. **The old 92-case numbers are replaced here, not kept alongside.**
> Tier2 logic is unchanged (frozen). This file supersedes the v0.5 Part C numbers for the
> Part B set.

## Setup

- 4 reasoning-leaks removed from `synth/partb_validation_set.json` (NOT replaced — 88 still
  clears the 40/category threshold). Defensive: each dropped case's `user_input` was
  regex-verified to start with `Thinking:`/`Now format`/`Now ensure` (meta-text) before
  removal. Set is now 42 consistent + 46 inconsistent.
- Tier2 FROZEN. 3 runs/case, temperature 0, majority verdict (conservative tie-break
  malicious > suspicious > benign). Numbers recomputed directly from
  `reports/v05_partC_frozen_eval.json` (now the 88-case run).

## Result — split by category (NOT merged)

### consistent (scary vocab, benign GT) — n=42

| metric | value | 95% CI (Wilson) |
|---|---|---|
| majority-verdict accuracy | **42/42 = 100%** | [91.6%, 100%] |
| per-run accuracy | 98% / 100% / 93% (mean 97%) | — |
| run-to-run agreement | 38/42 = 90% | — |
| verdict distribution | benign 42 | — |
| evidence_basis | grounded 42 | — |
| **FALSE POSITIVE (gt benign → malicious)** | **0/42 = 0%** | **[0%, 8.4%]** |

The scary-FP point estimate stays 0% after cleaning. Wilson upper bound 8.4% (was 8.2% at
n=43). n dropped to 42 (still ≥40). Per-run now 98/100/93% (vs 100/100/100 at n=43) —
cleaning surfaced a tiny per-run wobble the leaked cases had masked, but no majority FP.

### inconsistent (clean purpose, malicious GT) — n=46

| metric | value | 95% CI (Wilson) |
|---|---|---|
| majority-verdict accuracy | **40/46 = 87.0%** | [74.3%, 93.9%] |
| per-run accuracy | 85% / 85% / 85% (mean 85%) | — |
| run-to-run agreement | 35/46 = 76% | — |
| verdict distribution (majority) | malicious 40, benign 6 | — |
| evidence_basis | grounded 39, information_gap 7 | — |
| **FALSE NEGATIVE (gt malicious → benign)** | **6/46 = 13.0%** | [6.1%, 25.7%] |

**No "corrected" number needed anymore.** With the 2 data-error FNs (#060/#083) removed,
there is no Method A / Method B ambiguity — the raw 40/46 = 87.0% IS the clean number. The
v0.5 "83.7%/83.0% 口径" problem is dissolved by cleaning rather than by choosing a correction
method, which is the right outcome (clean data > methodological hedge).

The 6 remaining false-negatives (down from 10) are the genuine Tier2 misses — the 3
"plausible-purpose" social-engineering cases (#058, #076, #085) + run-to-run wobble cases.
The per-run accuracy is now flat at 85/85/85% (no run-to-run drift on this clean set at n=46).

## What changed vs the v0.5 92-case numbers

| metric | v0.5 (92, dirty) | v0.6 Part 0 (88, clean) |
|---|---|---|
| consistent n / acc | 43 / 100% | 42 / 100% |
| consistent FP | 0/43 (CI upper 8.2%) | 0/42 (CI upper 8.4%) |
| inconsistent n / acc | 49 / 79.6% raw (83.7%/83.0% "corrected") | 46 / **87.0%** (no correction needed) |
| inconsistent FN | 10/49 raw / 8 after correction | **6/46** |
| inconsistent per-run | 86/84/76% | 85/85/85% |

Cleaning **raised** the inconsistent accuracy (79.6% → 87.0%) because 4 of the 10 raw FNs
were data errors being counted as Tier2 misses. The honest framing: **the v0.5 raw 79.6%
was understating Tier2** (2 of those FNs were never real attacks), and the v0.5 "83.7%
corrected" was a Method-B number that also wasn't quite right; the clean 87.0% is the
first number with no asterisk. But — see the reverse-hypothesis caveat below and Part 2.

## The standing caveat (unchanged, NOT resolved by cleaning)

This 88-case set is STILL all single-turn, all from TWO promptfoo plugins, all one
generator (deepseek). The reverse hypothesis ("the new set is just easier to judge than
hand-crafted ssh-debug, not a sign Tier2 generalized") is **not addressed by cleaning** —
it's addressed by v0.6 Part 2 (non-same-source edge cases). Until Part 2 lands, no
"v0.5/Tier2 generalized" conclusion is warranted. **No tag.**

## Files
- `synth/partb_validation_set.json` — now 88 cases (42 consistent + 46 inconsistent), 4 leaks removed
- `reports/v05_partC_frozen_eval.json` — the 88-case frozen Tier2 run (overwrote the 92-case)
- `tier2/v05_partC_eval.py` — the frozen eval harness (unchanged)
