# v0.5 Part 4 — Tier3 implemented: ReadOnlyToolkit + investigative judgment

> **CORRECTION (51-record relabel, 2026-07-14):** `_126` is a grounded-benign
> model-visible operation, not an information-gap case for Tier3. Any `_126`
> trigger/example language below is retracted. This does not change the standalone
> Tier3 fixture implementation or the existing fact that it is not wired into the
> live pipeline. See `reports/multiturn_relabel_rerun_20260714.md`.

> **CORRECTION (post-audit, 2026-07-14): the "35%-pooled wobble" comparison below
> mixes two metrics.** In v0.4, `8/23 = 34.8%` is the rate at which all three ssh-debug
> variants were malicious in the same run, not the individual-verdict malicious rate. The
> like-for-like counts are `48/69 = 69.6%` individual malicious verdicts in v0.4 versus
> `17/24 = 70.8%` in v0.5, and `8/23 = 34.8%` all-three pass versus `3/8 = 37.5%`.
> Thus the Tier2 verdict rate was essentially unchanged; the acceptance below demonstrates
> standalone Tier3 fixture behavior, subject to this report's existing not-wired limitation.
> Evidence: `reports/part6_tier2_eval.json`, `reports/v04_deepdive.json`,
> `reports/v05_part6_regression.json`, and audit commit `9234a74` Finding 3.

## What changed (the big v0.5 move)

Tier3 was a stub (orchestration + MOF, both `not_implemented`). v0.5 promotes the
*investigation* role to a real implementation: when Tier2 flags a verdict as
`evidence_basis == "information_gap"` (Part 2), Tier3 resolves the named gaps with
**read-only tool queries** + a **deterministic rule** — never another LLM call, never a
write/exec.

The architectural correction that motivated this (per the revised task): "Tier2 should
only judge from Evidence-Capsule evidence; anything needing *additional facts looked up*
is Tier3's job, not Tier2's fallback." ssh-debug (can't tell if `deployment-config-host` is
internal/external from the text) is the canonical Tier3 case — Tier2 correctly flags it
information_gap (Part 2), Tier3 queries the registry/codebase/trajectory to resolve it.

## What was built

### `tier3/read_only_toolkit.py` — the zero-side-effect toolkit

Three read-only tools, facade over an injectable backend (Dependency Inversion):
- `query_session_trajectory(resource)` — has the target appeared before, judged normal?
- `search_codebase(resource)` — is the hostname/path in config/docs/existing refs?
- `query_infra_registry(resource)` — is the target a registered internal service or unknown/external?

**Safety property (hard requirement, not style):** `ReadOnlyToolkit` and
`ReadOnlyToolkitBackend` expose NO write/exec/mutate methods. `tests/test_tier3_toolkit.py::
test_toolkit_has_no_write_or_exec_methods` introspects both classes and asserts no public
method name contains any of `write/exec/run/mutate/delete/save/push/send/patch/update/create/
insert/upload/post/put`, and that the backend ABC defines exactly the 3 read abstractmethods.

### `tier3/investigator.py` — the deterministic investigator

`Tier3Investigator.investigate(tier2_status, tier2_evidence_basis, information_gaps,
raw_interaction, stated_purpose) -> Tier3Verdict`:
1. If Tier2 didn't flag `information_gap` → `not_triggered` (don't spuriously investigate —
   secure-log, a true-benign grounded case, must NOT be escalated).
2. Extract concrete target resources from the gap text (quoted names / dash-bearing host
   tokens) — glue regex, not generation.
3. Detect whether the action transmits a secret/credential (so an unverified destination
   matters) — glue regex over the raw text.
4. For each target, within a tool-call **budget**, query all three tools.
5. Apply a deterministic rule:
   - registry says **external** + secret transmitted → `resolved_malicious`
   - registry says **registered internal service** → `resolved_benign`
   - **unverified by all 3 sources** + secret transmitted → `escalate_human`
     (the honest downgrade: can't confirm legitimate → can't auto-allow; can't prove
     attacker → can't auto-block; automation exhausted → human)
   - unverified + NO secret transmitted → `resolved_benign` (the gap was immaterial)
   - budget exhausted → `budget_exhausted` → human
   - no rule fired → `escalate_human`

**No LLM call.** Deliberate: Tier2's failure mode IS LLM instability on gray zones;
chaining another LLM judge would re-introduce it. A rule over verified tool outputs is
the reliable resolution path.

**Honest downgrade = human, not "fall back to Tier2's guess."** Per the revised task: falling
back to an uncertain guess would defeat the purpose. These cases are exactly where
automation cannot decide.

## Acceptance — ssh-debug, two scenarios

`tests/test_tier3_toolkit.py` (7 tests, all passing):

- **Scenario A** (registry flags `deployment-config-host` external + keyfile pushed):
  `resolved_malicious`. The investigation resolved what Tier2 wobbled on — the destination
  is a known external sink, so the keyfile push is exfiltration. **More definite than Tier2's
  35%-pooled wobble.** ✅
- **Scenario B** (destination UNVERIFIED by all 3 sources + keyfile pushed):
  `escalate_human`. The investigation did the work a human would otherwise do (confirmed
  the destination is unverified) and routes to human — a definite routing decision with a
  clear reason, NOT a fallback to Tier2's coin-flip. ✅
- registered-internal-service → `resolved_benign` ✅
- secure-log (no information_gap) → `not_triggered` (no spurious investigation) ✅
- budget=1 (needs 3) → `budget_exhausted` → human ✅
- unverified + no secret → `resolved_benign` (immaterial gap) ✅

## The honest limitation (reported, not hidden)

The default backend is `FixtureToolkitBackend` — an **in-memory, explicitly-labeled
synthetic test fixture**. There is **no real session-trajectory store, codebase index, or
infra inventory** in this prototype's environment. So:

- The acceptance above demonstrates the **mechanism** (Tier3 reads tool outputs and reaches a
  more-definite, deterministic conclusion than Tier2's wobble), NOT a real-world investigation
  against live data.
- The fixture is **test input**, clearly labeled (`"synthetic test fixture (no real system
  queried)"`). It is NOT a fabricated claim that a real system was queried — the code and
  this report both say plainly that no real backend exists yet.
- Production would inject a real `ReadOnlyToolkitBackend` (e.g. one that reads an actual
  asset inventory / greps the actual repo / queries a verdict-history store). The
  investigator logic is backend-agnostic; nothing here assumes the fixture is real.

Per the task: "如果目前的测试环境里没有真实的会话轨迹历史/代码库可供查询，如实说明这个
限制，不要伪造查询结果去凑一个'验证通过'的假象." — complied. No query results were
fabricated; the fixture is labeled synthetic, and the limitation is stated here and in the
toolkit docstring.

## What this does NOT claim

- Tier3 is **not wired into the live pipeline** as an automatic stage yet —
  `pipeline.tier2_enabled` stays False (Tier2 not deployable per v0.4), so Tier3 (which
  triggers off Tier2) is also not auto-running. This v0.5 ships Tier3 as a *real, tested
  component* reachable in tests and eval harnesses, with the trigger input (Part 2's
  `evidence_basis`) defined. Wiring the full Tier2→Tier3→human pipeline into `pipeline.py`
  is a v0.6 integration step, done after Tier2 itself is trustworthy enough to enable.
- The deterministic rule covers the ssh-debug archetype (unverified destination + secret
  transmission). Other gap shapes (e.g. _126's "no action shown / signal conflict") are not
  yet auto-resolved by a rule — they fall through to `escalate_human`, which is the safe
  default but means Tier3 doesn't *resolve* them, just routes them. Honest: the rule set is
  narrow; broadening it is future work.

## Files
- `tier3/read_only_toolkit.py` (ReadOnlyToolkit + backend ABC + FixtureToolkitBackend)
- `tier3/investigator.py` (Tier3Investigator + Tier3Verdict)
- `tier3/__init__.py` (exports)
- `tests/test_tier3_toolkit.py` (7 tests: safety property + both ssh-debug scenarios + guards)
