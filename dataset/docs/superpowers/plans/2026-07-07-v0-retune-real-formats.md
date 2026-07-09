# v0 Re-tuning Plan — Real-Data Normalizers

**Date**: 2026-07-07  **Branch**: `build/v0-pipeline`
**Context**: The 23-task pipeline is complete and runs end-to-end, but the live run showed the source normalizers were tuned to simplified fixtures, not real data formats. This plan re-tunes the high-priority agent-specific sources (+ gtfobins + clawsentry) so v0 training data actually contains agent tool-call / indirect-injection / jailbreak / R-Judge data.

**Constraint**: Each fix task keeps the fixture-fallback (`RAW_DIR if exists else tests/fixtures/<src>`) so offline tests still pass, BUT the fixture must be updated to a SMALL real-format sample (2-4 records copied from `raw/<src>/`) so tests exercise the real format. The normalize must produce >0 records on the real `raw/<src>/` (verified by a live single-source run). Don't change license classifications. Preserve the unified-schema fields. Tests must stay green.

**Execution**: one fix subagent per source (TDD against the real-format fixture), then a re-run of the full pipeline, then commit the updated `processed/`+`reports/`.

---

## R1. injecagent — JSON arrays (not CSV)

Real: `raw/injecagent/data/test_cases_{ds,dh}_{base,enhanced}.json` are arrays of objects with `User Instruction` (benign user goal), `User Tool`, `Tool Response Template` (contains a `<Attacker Instruction>` placeholder — the indirect injection embedded in tool output), `Attacker Instruction` (the payload), `Attack Type`. Also `user_cases.jsonl` (benign user cases) + `attacker_cases_*.jsonl`.

**Fix** `scripts/normalize_injecagent.py`: read `data/test_cases_*.json` arrays (each object → one record): turns = `[user_direct: User Instruction, tool_output: Tool Response Template (with <Attacker Instruction>)]`; `is_malicious=True`, `attack_family=indirect_injection` (the spec: InjecAgent = indirect injection "外部内容里藏指令"), `instruction_origin=tool_output`, `risk_category=prompt_injection`, `confidence=high`, `target_resource=User Tool`, `stated_purpose=User Instruction`. Optionally also emit benign records from `user_cases.jsonl` (`is_malicious=False`, `attack_family=benign`). `_raw_id` from array index + file stem.

**Fixture**: replace `tests/fixtures/injecagent/sample.csv` with `tests/fixtures/injecagent/test_cases_sample.json` = a 2-3-element array copied (trimmed) from a real `test_cases_*.json`. Update `tests/test_injecagent.py` to assert the JSON-driven fields (attack_family `indirect_injection`, instruction_origin `tool_output`, is_malicious True, license_status ok).

## R2. hf_injections — datasets.load_from_disk (not CSV)

Real: `fetch_hf_injections` saved each dataset via `datasets.save_to_disk` → `raw/hf_injections/{hf_deepset,hf_jayavibhav,hf_imoxto}/dataset_dict.json` + parquet splits. The normalize looked for `*.csv` → 0 records.

**Fix** `scripts/normalize_hf_injections.py`: in `main()`, if `RAW_DIR/<src_key>` exists and contains `dataset_dict.json`, load via `datasets.load_from_disk(RAW_DIR/src_key)` and read its splits (concat train/test); map each dataset's columns to text+label (deepset: `text`/`label` or `text`/`label`-int; jayavibhav: `prompt`/`is_injection`; imoxto: `text`/`injection`). Keep the CSV-fallback for the fixture path (or update the fixture to a tiny `dataset_dict.json`-style — simpler: keep a CSV fixture for the offline test AND add a `load_from_disk` path for real data). Cleanest: try `load_from_disk` first (real), fall back to CSV (fixture). Binary label → `direct_injection`/`benign`, single_turn, `instruction_origin=user_direct`, `confidence=high`, gate-driven license (deepset ok, others needs_confirmation).

**Fixture**: keep `tests/fixtures/hf/*.csv` for the offline test (the CSV path), so the test still runs offline; the `load_from_disk` path is exercised live. Update test if needed to keep asserting the 3 sources + license split.

## R3. jailbreakbench — real data location

Real: the cloned repos have NO CSVs. Data is either (a) `raw/jailbreakbench/artifacts/attack-artifacts/<method>/{prompts,...}` per-method files, or (b) HF `JailbreakBench/JBB-Behaviors` (MIT). Inspect `raw/jailbreakbench/artifacts/attack-artifacts/GCG/` to see if prompt data is there as files; if not, fetch via `datasets.load_dataset("JailbreakBench/JBB-Behaviors")` (public, MIT) in `fetch_jailbreakbench` and have the normalize read it.

**Fix**: inspect the artifacts dir; if prompt files exist (e.g., a CSV/JSON per method under `attack-artifacts/<method>/`), read them; else change `fetch_jailbreakbench` to `datasets.load_dataset("JailbreakBench/JBB-Behaviors")` (catch errors → log+skip) and `normalize_jailbreakbench` to read the loaded dataset (`jailbreak_prompt`/`method`/`category` columns). Keep `attack_family=jailbreak_<method>`, `license_status=ok`, `confidence=high`, `notes` with the `domain-gap` caveat.

**Fixture**: update to a real-format sample (the chosen source's shape). Update test.

## R4. rjudge — real schema (label + contents)

Real: `raw/rjudge/data/<scenario>/<name>.json` are ARRAYS of records with `id`, `scenario`, `profile`, `goal`, `contents` (nested: list of turn-groups, each a list of `{role,content,thought}`), `label` (1=unsafe, 0=safe), `risk_description`, `attack_type`. The AttributeError came from `raw/rjudge/config/data_schema.json` (a dict, not a list) being iterated as keys.

**Fix** `scripts/normalize_rjudge.py`: only process `data/*/*.json` (skip `config/`); for each file, require `isinstance(data, list)` (skip non-list). For each record: `is_malicious = (label == 1)`; `modality=multi_turn`; turns = flatten `contents` (each turn-dict → `make_turn(role, content, "user_direct"|"agent_plan")`); `attack_family = attack_type or ("goal_hijack" if unsafe else "benign")`; `purpose_capability_consistent = not unsafe`; `risk_category = unauthorized_action if unsafe else benign`; `confidence=high`; `notes = risk_description`; `structured_action.target_resource = scenario`. license_status=needs_confirmation (unchanged, held out).

**Fixture**: replace `tests/fixtures/rjudge/sample.json` with a real-format array (2 records: one label=1, one label=0, copied/trimmed from a real file). Update test to assert `is_malicious` from `label`, multi_turn, needs_confirmation.

## R5. gtfobins — extensionless `_gtfobins/*` YAML docs

Real: `raw/gtfobins/_gtfobins/<binary>` files have NO extension; each is a single YAML doc delimited by `---`/`...` with top-level `name`/`comment`/`functions` (each function → list of `{comment,code,...}` or with `contexts`). The normalize's `.md`/`.yml`/`.yaml` suffix filter excluded them → 0 records. (CONTRIBUTING.md confirms the format.)

**Fix** `scripts/normalize_gtfobins.py`: glob `raw/gtfobins/_gtfobins/*` (files, any extension incl. none) + keep `.yml`/`.yaml`; for each, `data = yaml.safe_load(f.read_text())` (single YAML doc; `---`/`...` markers are fine for yaml.safe_load); if `data` is a dict with `functions`, iterate `functions[func]` items → records (code field = command pattern). Drop the `_frontmatter`/`_load_entries` `.md` branch (GTFOBins isn't markdown) OR keep it harmless. `action_type=exec`, `attack_family` from `_FAM`, `confidence=medium`, command-patterns-only, `license_status=ok`, deterministic sha1 ids.

**Fixture**: replace `tests/fixtures/gtfobins/tar.yml` with `tests/fixtures/gtfobins/_gtfobins/tar` (extensionless, real `---`/`...` format, trimmed). Update test to point RAW_DIR at `tests/fixtures/gtfobins` and assert the families. (Keep the existing assertions: `{shell_spawn, privilege_escalation, file_read} ⊆ fams`, exec, ok, medium.)

## R6. agentdojo — class-based suites (hardest)

Real: `raw/agentdojo/src/agentdojo/default_suites/v1_1_2/<suite>/user_tasks.py` defines `UserTaskNN(BaseUserTask)` classes with `@task_suite.update_user_task` decorators and a `PROMPT = "..."` class attribute (the benign user instruction). `<suite>/injection_tasks.py` defines injection task classes with a payload (inspect `injection_tasks.py` for the payload/injectable attribute name). The fixture's module-level `USER_TASKS`/`INJECTIONS` lists don't exist in real AgentDojo.

**Fix** `scripts/normalize_agentdojo.py`: walk `default_suites/v1*/<suite>/{user_tasks,injection_tasks}.py` with `ast`:
- `user_tasks.py`: find class defs with a `PROMPT` assignment (string literal) → benign record (turn: user_direct=PROMPT, multi_turn, attack_family=benign, is_malicious=False, confidence=high, license_status=ok). target_resource=suite.
- `injection_tasks.py`: inspect the real injection-task class structure (the payload string — likely a class attr like `GOAL`/`payload`/`injectable_parameters`/a `benchmark_key` + a payload). Extract the payload text → injection record (turn: tool_output/retrieved_content=payload, attack_family=indirect_injection_<suite>, is_malicious=True, confidence=high). If the payload attribute name is ambiguous, inspect 1-2 real `injection_tasks.py` files to find it and document in the report.
- Filter via `validate_record`; deterministic ids (class name based, sha1 of payload).

**Fixture**: replace `tests/fixtures/agentdojo/slack.py` with a real-shape mini-suite: `tests/fixtures/agentdojo/<suite>/user_tasks.py` + `injection_tasks.py` copied/trimmed from a real suite (1-2 user tasks with `PROMPT`, 1-2 injection tasks with the payload attr). Update the test to assert benign + injection records from the class-based parse. (If a real trimmed fixture is hard to make compile-free, use `ast` on it — no exec.)

## R7. clawsentry_rules — fetch mkdir bug

Real: `fetch_clawsentry_rules` does `shutil.copy(LOCAL, pathlib.Path("raw/clawsentry_rules/attack_patterns.yaml"))` but `raw/clawsentry_rules/` doesn't exist → `FileNotFoundError`. (LOCAL `/home/hjy/ClawSentry/.../attack_patterns.yaml` exists in this env.)

**Fix** `scripts/fetch_clawsentry_rules.py`: `pathlib.Path("raw/clawsentry_rules").mkdir(parents=True, exist_ok=True)` before the `shutil.copy`. (And if LOCAL is absent, the clone path already mkdir's via clone_or_pull.) No normalize change (it already works on the fixture; live it'll read the copied real yaml). Verify live: copy succeeds, normalize reads real `attack_patterns.yaml` → >0 records.

**Fixture/test**: unchanged (the test uses the fixture via RAW_DIR monkeypatch). Optionally add a mkdir to be safe. Just verify the fetch no longer FileNotFound-errors and the live normalize produces records.

---

## After R1–R7: re-run + commit

- `python3 scripts/run_pipeline.py --all` (resume; clones exist) → re-merge/dedup/split/report.
- Verify per-source counts: agentdojo/injecagent/hf_deepset/jailbreakbench/rjudge/gtfobins/clawsentry_rules should now be >0 (real-backed). rjudge/bipia/purplellama/llamafirewall/mitre stay needs_confirmation (held out of training).
- Commit updated `processed/*.jsonl` + `reports/` + any fixture/normalize/test changes.
- Update `reports/coverage_gaps.md` if the gap picture changed (it should shrink for the fixed sources).
