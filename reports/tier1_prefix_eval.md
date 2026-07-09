# Tier 1 Prefix-Level Evaluation Report (the paper's core, previously untested)

arXiv:2605.01143 evaluates its detector at the **prefix** level: for each
multi-turn interaction, every partial history `S1:t` (turns 1..t) is an
evaluation instance, and a prefix is labeled adversarial (`y=1`) if the
**whole interaction** ultimately leads to an unsafe execution event
(sensitive read co-occurring with exfiltration, or unauthorized privileged
execution). The operational objective is to flag a risky trajectory **before**
the harmful action is executed.

This v0 never ran that evaluation until the first audit pass. This report is
its honest result — **updated after the 2026-07-09 leakage fix** that removed
the `structured_action` future-info channel from `extract_features`.

Implementation: `tier1/prefix_eval.py`. A t-turn record yields t prefixes
(turns 1..t). Each prefix keeps the *whole-interaction* label (faithful to the
paper), and features are extracted on the truncated prefix. Model = the
retrained `xgboost_full.json` (40 features, after the summarize-leakage fix,
promptfoo dilution, **and the structured_action-leakage fix**).

## Results (post structured_action-leakage fix)

| Split | records | prefixes | adv-prefixes | AUC | F1 | Prec | Rec | DetRate |
|-------|---------|----------|--------------|-----|-----|------|-----|---------|
| test_indist | 275 | 275 | 223 | 0.842 | 0.887 | 0.877 | 0.897 | 0.829 |
| test_holdout | 793 | 793 | 793 | NaN | 0.781 | 1.000 | 0.641 | 0.641 |
| synth_xgboost_paper | 3200 | 10400 | 5200 | 0.934 | 0.859 | 0.818 | 0.906 | 0.554 |

(`test_indist` / `test_holdout` are mostly single-turn, so prefix eval there
is trivial — 1 prefix each. `synth_xgboost_paper` is the meaningful multi-turn
test.)

### What changed vs the pre-fix run (the structured_action confound is gone)

Before the fix, the model read the record-level `structured_action.action_type`
(a near-label-proxy AND the whole-record final action) via
`task_tool_mismatch_flag`. That field was attached to **every** prefix,
including t=1, so a t=1 prefix already "knew" the trajectory ended in exfil/exec.
Result before: the model flagged **all 1600** adversarial synth records at t=1
(`early = {1: 1600}`), AUC 0.993 — a confounded "early detection."

After the fix (`task_tool_mismatch_flag` reserved at 0; `extract_features`
reads no record-level field other than `turns`):

| Family | t=1 mean prob | first-flag distribution | note on t=1 content |
|--------|---------------|--------------------------|----------------------|
| split_exfil | 0.998 | {1: 400} | turn 1 = "Read /etc/shadow" (sensitive) — genuine |
| staged_burst | 0.998 | {1: 400} | turn 1 = "Read /etc/shadow" (sensitive) — genuine |
| context_laundering | 0.973 | {1: 400} | turn 1 = "Fetch weather URL" (**benign text**) |
| privilege_drift | 0.647 | {1: 220, 2: 180} | turn 1 = "List ./src" (**benign text**) |

Two honest changes:

1. **privilege_drift now genuinely waits.** Before the fix all 400 were flagged
   at t=1. After the fix, **180/400 are first flagged at t=2** — the t=1 prefix
   ("List ./src", action=unknown) is genuinely not flagged, and the model only
   flags at t=2 when "Write a cleanup script" / privileged action appears. The
   t=1 mean prob dropped to 0.647 (was 0.841), and t=3 to 0.468 (was 0.470). This
   is the de-confounding working: the structured_action future-info channel that
   forced a t=1 flag is gone.

2. **AUC dropped 0.993 → 0.934** on synth, and the per-prefix DetectionRate
   moved 0.488 → 0.554. The lost "easy" flags were the leaked-structured_action
   ones; what remains is genuine content-based detection (split_exfil/staged_burst
   t=1 sensitive reads) plus a residual template-identity signal.

## The remaining, honest shortcoming — template identity is still learned

`context_laundering` is STILL flagged at t=1 for all 400 records (mean prob
0.973) even though its t=1 text ("Fetch the weather from {url}") is genuinely
benign-looking. With the structured_action channel removed, this t=1 flag can
only come from **other features visible at t=1** that still fingerprint the
synthetic template — e.g. `tool_web_fetch` ("fetch … https://"), the specific
parameterized phrasing, and the turn-count/structure. This is **not** future-info
leakage (it reads only t=1-visible content), but it **is** template memorization:
the model recognizes the family from the templated surface form, not from
genuine escalating risk.

**Implication:** the "flag the trajectory before the harm" property is now
**partially** demonstrated — privilege_drift waits honestly, split_exfil/
staged_burst flag legitimately at t=1 (the sensitive read is already visible),
but context_laundering still flags early via template identity. A fully fair
early-detection eval still needs **non-templated** multi-turn adversarial
trajectories so the model cannot memorize family identity from surface form.

## Confounded evaluation — what was fixed and what remains

1. **FIXED — whole-record `structured_action` future-info channel.**
   `extract_features` no longer reads `structured_action`; the one feature that
   did (`task_tool_mismatch_flag`) is reserved at 0. A t=1 prefix now carries no
   information about the trajectory's final action. Verified: flipping a
   record's `structured_action.action_type` leaves the full 40-dim feature
   vector identical; index 24 == 0.0 for all records.

2. **REMAINS — synthetic template identity is learned.** The four families are
   structurally distinct enough that visible t=1 surface form (verbs, phrasing,
   tool one-hots) still fingerprints the family for `context_laundering` (and
   ~220/400 `privilege_drift`). This needs non-templated multi-turn test data,
   not a feature fix.

## Per-prefix probability profile (synth, per family, post-fix)

```
split_exfil:       t1=0.998(1.00)  t2=1.000(1.00)
context_laundering:t1=0.973(1.00)  t2=0.721(1.00)  t3=0.994(1.00)  t4=1.000(1.00)
privilege_drift:   t1=0.647(0.55)  t2=0.835(1.00)  t3=0.468(0.45)  t4=0.999(1.00)
staged_burst:      t1=0.998(1.00)  t2=0.992(1.00)  t3=1.000(1.00)
```
(format: mean_prob(frac_flagged@0.5); first-flag distribution per family:
split_exfil/staged_burst/context_laundering → all at t=1; privilege_drift →
{1:220, 2:180})

## Honest conclusion

- The prefix-level eval (the paper's core) **now runs on a leakage-free feature
  extractor** and produces real numbers (`reports/tier1_prefix_eval.json`).
- The `structured_action` future-info confound is **removed**: privilege_drift
  now honestly waits to t=2 for 180/400 records instead of false-flagging at t=1.
- A residual confound **remains**: `context_laundering` still flags at t=1 via
  learned template identity (visible t=1 surface form), not via future info.
- A fully fair early-detection eval needs non-templated multi-turn test data
  so the model cannot memorize family identity — unchanged v1 roadmap.

## v0 → v1 for prefix eval
- Curate real / non-templated multi-turn adversarial trajectories so the model
  cannot memorize family identity from surface form (the remaining confound).
- Report per-prefix latency and the early-detection lead time (turns before the
  harmful action at which the model first flags) on fair, un-templated data.
