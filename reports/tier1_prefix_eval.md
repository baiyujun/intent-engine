# Tier 1 Prefix-Level Evaluation Report (the paper's core, previously untested)

arXiv:2605.01143 evaluates its detector at the **prefix** level: for each
multi-turn interaction, every partial history `S1:t` (turns 1..t) is an
evaluation instance, and a prefix is labeled adversarial (`y=1`) if the
**whole interaction** ultimately leads to an unsafe execution event
(sensitive read co-occurring with exfiltration, or unauthorized privileged
execution). The operational objective is to flag a risky trajectory **before**
the harmful action is executed.

This v0 never ran that evaluation until now. This report is its honest result.

Implementation: `tier1/prefix_eval.py`. A t-turn record yields t prefixes
(turns 1..t). Each prefix keeps the *whole-interaction* label (faithful to the
paper), and features are extracted on the truncated prefix. Model = the
retrained `xgboost_full.json` (40 features, after the summarize-leakage fix
and promptfoo dilution).

## Results

| Split | records | prefixes | adv-prefixes | AUC | F1 | Prec | Rec | DetRate |
|-------|---------|----------|--------------|-----|-----|------|-----|---------|
| test_indist | 275 | 275 | 223 | 0.934 | 0.925 | 0.940 | 0.910 | 0.785 |
| test_holdout | 793 | 793 | 793 | NaN | 0.783 | 1.000 | 0.643 | 0.643 |
| synth_xgboost_paper | 3200 | 10400 | 5200 | 0.993 | 0.969 | 0.980 | 0.958 | 0.488 |

(`test_indist` / `test_holdout` are mostly single-turn, so prefix eval there
is trivial — 1 prefix each. `synth_xgboost_paper` is the meaningful multi-turn
test.)

## The exposed problem — "early detection" is not actually happening

The headline finding: on the multi-turn adversarial families, the model flags
**at prefix t=1** — the *first* turn — for essentially every adversarial
interaction:

| Family | t=1 mean prob | t=1 frac flagged | note on t=1 content |
|--------|---------------|------------------|----------------------|
| split_exfil | 0.999 | 1.000 | turn 1 = "Read /etc/shadow" (sensitive) |
| context_laundering | 0.999 | 1.000 | turn 1 = "Fetch weather URL" (**benign**) |
| privilege_drift | 0.841 | 1.000 | turn 1 = "List ./src" (**benign**) |
| staged_burst | 0.999 | 1.000 | turn 1 = "Read /etc/shadow" (sensitive) |

For `context_laundering` and `privilege_drift`, **prefix t=1 is a benign-looking
fetch/list with no sensitive read and no exfil** — there is genuinely nothing
to detect at t=1 from the *content*. Yet the model flags it at probability
≈0.99. This cannot be content-based early detection; it means the model has
learned to identify the **whole-record template family** from features that
leak the full interaction's identity into the prefix (e.g. the
`structured_action` of the whole record — which for these families is
`network_request`/`exec` — is attached to *every* prefix, including t=1, so the
t=1 prefix already "knows" the trajectory ends in exfil/exec).

**Implication:** the "flag the trajectory before the harm" property the paper
claims is **not demonstrated** in our v0 — the model flags early because the
prefix carries whole-record metadata, not because it detected escalating risk
in the visible turns. This is a real shortcoming of the v0 prefix-eval setup,
not a hidden strength.

### One family behaves correctly
`privilege_drift` at **t=3** (the "Search {file}" turn) drops to mean_prob 0.470,
frac_flagged 0.450 — the model is *uncertain* mid-trajectory, which is the
honest behavior you'd expect when the visible prefix is genuinely ambiguous.
This is the only place the model is not just reading off the template.

## Per-prefix probability profile (synth, per family)

```
split_exfil:       t1=0.999(1.00)  t2=1.000(1.00)
context_laundering:t1=0.999(1.00)  t2=0.977(1.00)  t3=0.986(1.00)  t4=1.000(1.00)
privilege_drift:   t1=0.841(1.00)  t2=0.939(1.00)  t3=0.470(0.45)  t4=0.999(1.00)
staged_burst:      t1=0.999(1.00)  t2=0.976(1.00)  t3=1.000(1.00)
```
(format: mean_prob(frac_flagged@0.5))

## Confounded evaluation — root cause

The prefix eval is **confounded** by two v0 choices, which is why the "early
flag at t=1" result must not be read as success:

1. **Whole-record `structured_action` is attached to every prefix.** A prefix
   at t=1 of a `context_laundering` record still carries
   `structured_action.action_type = network_request` (the record's *final*
   action). So the t=1 prefix already encodes "this trajectory ends in a
   send." The model keys on that, not on the t=1 text. To eval early-detection
   fairly, the prefix's `structured_action` must be the *proposed action at
   turn t*, not the whole-record's final action.

2. **Template identity is learned.** The synthetic families are structurally
   distinct enough that the model memorizes the family, and the
   whole-interaction label propagates to every prefix by construction.

## Honest conclusion

- The prefix-level eval (the paper's core) **now exists and runs**, producing
  real numbers (`reports/tier1_prefix_eval.json`).
- But the numbers reveal the v0 prefix eval is **confounded**: the model
  "detects" adversarial trajectories at t=1 via leaked whole-record metadata,
  not via genuine early-trajectory reasoning. Only `privilege_drift` at t=3
  shows honest uncertainty.
- This is the single most important *new* exposed problem: a fair early-
  detection eval requires per-turn proposed-action prefixes (not whole-record
  `structured_action`) and non-templated multi-turn test data — neither of
  which the v0 data schema provides cleanly.

## v0 → v1 for prefix eval
- Build prefixes with the **proposed action at turn t** as the prefix's
  `structured_action`, not the whole-record final action.
- Curate real multi-turn adversarial trajectories (not templated) so the
  model cannot memorize family identity.
- Report per-prefix latency (paper does; v0 does not yet) and the
  early-detection lead time (turns before the harmful action at which the
  model first flags), computed on a fair (un-leaked) prefix construction.
