# v0.5 Part B — validation-set expansion via promptfoo (Tier2 FROZEN, no prompt edits)

> **CORRECTION (post-audit, 2026-07-14): the `ground_truth_*` fields below are
> generator/plugin-intended labels, not independently adjudicated ground truth.** Both custom
> plugin graders explicitly say `Placeholder grader (generation-only use; not evaluated here)`;
> the recorded workflow generated cases but retained no executed grader result or human
> adjudication for the final labels. Claims below that a label "is right" or that the set is not
> template-derived therefore describe generator intent, not verified semantic truth. The 92-case
> artifact is recoverable at `770ae5e:synth/partb_validation_set.json` (Git object
> `1c9d8d8...`). Commit `4ae0131` overwrote the current path with the 88-case clean set (object
> `daf9927...`), so the current file no longer reproduces this report. Evidence: the two files in
> `synth/plugins/`, `synth/partb_full.yaml`, and audit commit `9234a74` Findings 6-7.

## How it was generated (not hand-written)

Two `file://` custom plugins (promptfoo's schema requires `generator` + `grader`; the
`generator` template uses `{{n}}`/`{{purpose}}`/`{{outputFormat}}`):
- `synth/plugins/purpose_capability_inconsistent.yaml` — clean stated purpose, but action
  capability does NOT match → inconsistent → malicious
- `synth/plugins/scary_vocab_consistent.yaml` — scary vocab, but action fully matches a
  benign local purpose → consistent → benign

**Provider blocker, honestly reported + resolved:** promptfoo's redteam generation
defaults to a cloud `gpt-5.5` generator that needs `OPENAI_API_KEY` (which I don't have).
Per your point ("换一个 api 就行"), I pointed `redteam.provider` at our company deepseek
(kspmas OpenAI-compatible gateway, reusing `TIER2_LLM_API_KEY`) and set
`PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true` — one config block, generation then
worked fully on our gateway. No hand-written generation scripts.

## Generation + cleaning (glue only — cleaning/dedup, NOT sample generation)

- `partb_full.yaml`: 45 + 45 = 90 generated. `partb_topup.yaml`: +25 (inconsistent
  needed top-up because that batch had 18 near-exact duplicates at temp 0.85; raised
  topup temp to 1.1).
- **Reasoning-leak:** deepseek-v4-pro is a reasoning model and leaked CoT into `content`
  ("Thinking: We need to generate...", "(~180 chars)" self-checks). v0.4 hit the same
  behavior. Cleaned with regex + meta-utterance patterns (NOT sample rewriting).
- Final: **92 distinct cases — 49 inconsistent + 43 consistent** (both clear the 40
  threshold). Saved to `synth/partb_validation_set.json` (full per-case JSON).
- 2 residual leaks slipped into the inconsistent set as #060/#083 — **flagged as data-quality
  errors in Part C, not counted as Tier2 failures** (they aren't real attacks; the ground-truth
  label is wrong, not the judge).

## Honest quality caveats

- 18 near-exact duplicates appeared in the inconsistent batch at temp 0.85 (different
  generation batches, same output) → topup at temp 1.1 supplied 24 fresh, dedup to 49 distinct.
- 2 residual reasoning-leaks mislabeled as inconsistent (#060, #083) — corrected in Part C.
- A few inconsistent cases are SQL-injection / unsafe-code-gen without an explicit exfil verb
  — these are correctly malicious (capability mismatch) even though my crude "exfil verb"
  spot-check flagged them; the label is right, the spot-check was too narrow.
- Action-type diversity confirmed: file-exfiltration, network-egress, privilege-escalation
  (sudoers/setfacl/setuid/cron), unsafe-code-gen (yaml.load/eval/pickle/dynamic-SQL),
  credential-read-then-send; benign: file-inspection, log-aggregation, permission-review,
  local-config-check, secret-presence-check. Not template word-swaps.

## Constraint compliance

- Tier2 FROZEN: no prompt / evidence_basis / rule edits this round. ✓
- No hand-written generation scripts; only cleaning/dedup glue; samples by promptfoo. ✓
- Full raw data in `synth/partb_validation_set.json` AND pasted inline in the reply to you. ✓

## Full raw JSON

See `synth/partb_validation_set.json` (92 cases, each with `category` /
`ground_truth_consistent` / `ground_truth_verdict` / `user_input` / `plugin_source`).
The complete per-case text is also pasted in the chat reply.
