# Agent Intent-Recognition Dataset (v0) — Design Spec

- **Date**: 2026-07-07
- **Status**: Approved (brainstormed), pending spec review
- **Goal**: Build a reproducible fetch/normalize/dedup/split/synth/report pipeline that produces a v0 training+evaluation dataset for an Agent **intent-recognition** module (ClawSentry / LlamaFirewall–style guardrail), classifying user input and agent actions by risk level and intent-vs-stated-purpose consistency.
- **Scope this session**: Full end-to-end run — install deps, fetch+normalize every reachable source (failures logged & skipped), dedup, split, small-scale synth, reports → deliver a **populated** `dataset/` with `unified.jsonl` + 4 splits + reports.

---

## 1. Repo, environment, layout

- **Project root**: `/home/hjy/dataset/` (own git repo; unrelated to the CNVD workspace at `/home/hjy`).
- **Python env**: venv at `dataset/.venv` (gitignored) isolating heavy deps (torch, sentence-transformers).
- **Pinned deps** (`requirements.txt`): `requests`, `datasets`, `huggingface_hub`, `sentence-transformers`, `numpy`, `pandas`, `scikit-learn`, `matplotlib`, `pyyaml`, `mitreattack-python` (optional; fallback to raw STIX JSON parse). `torch` arrives transitively via `sentence-transformers`.
- **Directory layout** (spec's structure + small additions):
  ```
  dataset/
  ├── raw/<source>/                 # original downloads/clones, untouched
  ├── processed/
  │   ├── per_source/<source>.jsonl  # idempotent normalized slices (gitignored)
  │   ├── unified.jsonl              # merged full set
  │   ├── train.jsonl
  │   ├── val.jsonl
  │   ├── test_indist.jsonl
  │   └── test_holdout_family.jsonl
  ├── synthetic/
  │   ├── synthetic.jsonl
  │   └── redteam_candidates.jsonl  # dry-run this session
  ├── scripts/
  │   ├── fetch_<source>.py
  │   ├── normalize_<source>.py
  │   ├── merge_unified.py
  │   ├── dedup.py
  │   ├── split.py
  │   ├── synth_generate.py
  │   ├── build_report.py
  │   └── run_pipeline.py            # thin orchestrator + --sources + resume
  ├── reports/
  │   ├── data_card.md
  │   ├── coverage_gaps.md
  │   ├── fetch_manifest.json        # per-source fetched_at + source_ref + status
  │   ├── dedup_report.json
  │   ├── split_report.json
  │   ├── fetch_errors.log
  │   └── figures/*.png
  ├── docs/superpowers/specs/        # this spec
  ├── Makefile
  ├── requirements.txt
  ├── .gitignore
  └── README.md                       # reproduce instructions
  ```
- **ClawSentry**: already cloned at `/home/hjy/ClawSentry`; `fetch_clawsentry_rules.py` reuses the local `src/clawsentry/gateway/attack_patterns.yaml` if present, else clones `AI45Lab/ClawSentry`.

## 2. Unified schema

The spec's schema is kept verbatim. **Three additions** and **one idempotency refinement**:

### Added fields
- `license_status` (top-level): `ok | needs_confirmation | excluded`. **Only `ok` enters train/val/test.** Drives the license gate (§3).
- `source_ref` (top-level): commit SHA / HF revision / `null` — for reproducibility & incremental refresh.
- `attack_stage_precursor` (inside `label`): bool — for Step 3 "harmless first step" samples (avoids polluting the single-turn classifier).

### Idempotency refinement
Each `normalize_<source>.py` **overwrites** `processed/per_source/<source>.jsonl` (no duplicates on re-run); `merge_unified.py` concatenates slices → `unified.jsonl`. Same end state as appending, safe to re-run any single source.

### `id` format
`<source>_<originalid>` where `originalid` is the source's native id if present, else a deterministic hash of the canonical text (sha1, truncated) — stable across re-runs.

## 3. License policy (conservative default + allowlist)

**Principle (user-directed)**: only *known* licenses (MIT, Apache-2.0, GPL-3.0) → `license_status=ok` → eligible for train/val/test. All *unknown / custom / no-license* sources → `needs_confirmation`, kept in `unified.jsonl` for statistics/observation only, **held out of all training splits** until legally confirmed. This narrows v0 coverage but avoids training on un-cleared data.

**Allowlist mechanism**: `scripts/license_config.yaml` lists each source's `license_status` and `license_spdx`. Flipping a source to `ok` (after legal sign-off) is a one-line config change + re-run of `split.py` — supports the "逐个放行" workflow without touching fetch/normalize code.

### Verified license table (probed 2026-07-07)
| Source | License | `license_status` |
|---|---|---|
| AgentDojo (`ethz-spylab/agentdojo`) | MIT | `ok` |
| InjecAgent (`uiuc-kang-lab/InjecAgent`) | MIT (LICENCE) | `ok` |
| BIPIA (`microsoft/BIPIA`) | custom (NOASSERTION) | `needs_confirmation` |
| R-Judge (`Lordog/R-Judge`) | **none** (no LICENSE) | `needs_confirmation` |
| PurpleLlama CyberSecEval (`meta-llama/PurpleLlama`) | custom (Llama Community) | `needs_confirmation` |
| HF `deepset/prompt-injections` | Apache-2.0 | `ok` |
| HF `jayavibhav/prompt-injection` | none | `needs_confirmation` |
| HF `imoxto/prompt_injection_cleaned_dataset-v2` | none | `needs_confirmation` |
| JailbreakBench (`JailbreakBench/jailbreakbench` + `artifacts`) | MIT (repo); artifacts may carry a separate usage agreement | `ok` for repo-derived data; artifacts fetched only if no ToU gate, else skipped+logged (never bypass) |
| AdvBench (`llm-attacks/llm-attacks` CSV) | MIT | `ok` (avoid auto-gated HF `walledai/AdvBench`) |
| GTFOBins (`GTFOBins/GTFOBins.github.io`) | GPL-3.0 (copyleft; noted) | `ok` |
| LOLBAS (`LOLBAS-Project/LOLBAS`) | GPL-3.0 (copyleft; noted) | `ok` |
| MITRE ATT&CK (`mitre-attack/attack-stix-data`) | custom (ATT&CK Terms of Use) | taxonomy use `ok`; sample-derivation `needs_confirmation` |
| ClawSentry `attack_patterns.yaml` (`AI45Lab/ClawSentry`) | MIT | `ok` |
| LlamaFirewall rules (`meta-llama/PurpleLlama`) | custom | `needs_confirmation` |
| OWASP Agentic/LLM Top 10 | OWASP docs (reference) | `ok` (taxonomy only, no samples) |
| Self-generated synthetic + near-dup pairs | own | `ok` |

> Any of these can be overridden in `license_config.yaml`; data_card will show verification provenance so reviewers can challenge a classification.

## 4. Source-by-source plan

### A. Agent / tool-call (priority)

**A1. AgentDojo** — `git clone --depth 1`. Data in `src/agentdojo/agentdojo/default_suites/v1/<suite>/` (Python tasks + injection tasks).
- Benign tasks → `is_malicious=false`, `risk_category=benign`, `attack_family=benign`, `modality=multi_turn`; extract user instruction + expected tool-call sequence into `turns` (`user_direct` + `agent_plan`) and `structured_action` per tool.
- Injection tasks → `is_malicious=true`, `attack_family=indirect_injection[_<suite>]`, `instruction_origin=tool_output|retrieved_content`, `confidence=high`.
- Limit: fixed tool suites (slack, todo, routeros, …) → bounded domain coverage.

**A2. InjecAgent** — clone. CSVs in `data/` (`user_data`, `injection`, `injection_type`, …).
- Each row → `is_malicious=true`, `attack_family` from `injection_type` (→ `indirect_injection`, `goal_hijack`, `credential_exfil`, …), `modality=single_turn`, `instruction_origin=tool_output|retrieved_content`, `confidence=high`, `risk_category`→OWASP prompt-injection/agentic-unauthorized-action.
- Limit: indirect injection via tool outputs only.

**A3. BIPIA** (`microsoft/BIPIA`, `needs_confirmation`) — clone (+ HF if data lives there). Indirect injection incl. multimodal → `attack_family=indirect_injection[_multimodal]`, `instruction_origin=retrieved_content|tool_output`, `confidence=high`. Cross-dedup with InjecAgent in Step 4. Held out of training (custom license).

**A4. R-Judge** (`Lordog/R-Judge`, `needs_confirmation`) — clone. Agent trajectories + safety/critique labels.
- Each record → `modality=multi_turn`; `is_malicious` from safety label; `purpose_capability_consistent` derived from critique (R-Judge judges intent-vs-action); `risk_category` mapped from its categories; `confidence=high` (human-annotated).
- Rich source for `purpose_capability_consistent` + multi_turn. Held out of training (no license).

**A5. PurpleLlama CyberSecEval** (`meta-llama/PurpleLlama`, `needs_confirmation`) — shallow clone. Focus on prompt-injection / agent-misalignment subsets in `cyberseceval/`. `is_malicious=true` for adversarial prompts, `attack_family` per subset, `confidence=high`. Held out of training (custom license).

### B. General prompt injection / jailbreak

**B1. HF `deepset/prompt-injections`** (`datasets.load_dataset`) — binary label → `direct_injection`/`benign`, `modality=single_turn`, `instruction_origin=user_direct`, `confidence=high`. Limit: binary only, no subfamily.

**B2/B3. HF `jayavibhav/prompt-injection` & `imoxto/prompt_injection_cleaned_dataset-v2`** (`needs_confirmation`) — same mapping; held out of training (no license).

**B4. JailbreakBench** — source from the **MIT GitHub repos** (`jailbreakbench` + `artifacts`), not the no-license HF dataset. `is_malicious=true`, `attack_family` from method (`GCG`, `PAIR`, `AutoDAN`, …→ `jailbreak_<method>`), `risk_category=goal_hijack|prompt_injection`, `modality=single_turn`, `instruction_origin=user_direct`, `confidence=high`.
- **Domain-gap caveat (user-raised)**: these are *general content-safety jailbreaks*, not representative *Agent action-risk* samples — better suited to the "recognize injection/goal-hijack semantic signal" sub-capability. Keep the source marker in labels; plan a **per-source ablation** to measure whether they help or add noise for the Agent scenario. Note in `coverage_gaps.md`.
- **Artifacts ToU**: if the official artifacts require accepting a usage agreement that we cannot programmatically accept, **skip those artifacts and log** — never bypass access limits.

**B5. AdvBench** — use the **MIT `llm-attacks` repo** `data/advbench/harmful_behaviors.csv` (avoid the auto-gated HF `walledai/AdvBench`). `is_malicious=true`, `attack_family=advbench_gcg`/`harmful_intent`, `risk_category=goal_hijack|prompt_injection`, `modality=single_turn`, `confidence=high`. Same domain-gap caveat + ablation as JailbreakBench.

### C. Command / behavior structured negatives

**C1. GTFOBins** (GPL-3.0) — clone; parse `_gtfobins/*.md` YAML frontmatter `functions:`. Each (binary, function, command) tuple → `structured_action.action_type=exec`, `target_resource=<binary>`, `stated_purpose` from the GTFOBins function category; `attack_family` mapped: `shell`→`reverse_shell`/`shell_spawn`, `sudo`/`suid`→`privilege_escalation`, `file-read`→`file_read`, `file-write`→`file_write`, `download`→`exfil`, `confidence=medium`.
- **Command patterns only — no complete payloads** (constraint).

**C2. LOLBAS** (GPL-3.0) — clone; YAML per binary (`Name`, `Commands`, `Category`, …). Windows analog of GTFOBins. `attack_family` from `Category` (`Download`→`network_request`, `AWL Bypass`→`defense_evasion`, `Credentials`→`credential_access`, `Compile`/`Scripts`→`code_exec`), `confidence=medium`. Windows-only limit.

**C3. MITRE ATT&CK** — download the **single enterprise STIX bundle** (latest) rather than the 128 MB full clone. Two uses:
1. **Taxonomy reference** (license-`ok`): build/validate the `attack_family` enum + OWASP mapping from tactics/techniques.
2. **Weak-labeled samples** (`needs_confirmation`, `confidence=low`): a small set of technique-description rewrites as "technique-mentioned" samples, `notes="MITRE technique rewrite; weak label; needs review"`. Held out of training (custom license).

### D. Existing guardrail rules → reverse-generate samples

**D1. ClawSentry `attack_patterns.yaml`** (MIT, local) — parse rules (name + regex/keywords + category); for each rule, **template-generate** N natural-language/command samples that hit the pattern. `confidence=medium`, `notes="rule_derived: <rule>"`, `source_dataset=clawsentry_rules`.

**D2. LlamaFirewall rules** (`needs_confirmation`, custom) — locate scanner/rule defs in PurpleLlama; same reverse-generation. If LlamaFirewall uses ML classifiers rather than regex rules (few rule-derivable samples), note in `coverage_gaps.md`. Held out of training.

### E. Taxonomy reference (defines `risk_category` enum)

Fetch OWASP **Agentic AI Top 10** (`genai.owasp.org/resource/agentic-ai-threats-and-mitigations/`) + **LLM Top 10 2025** (`.../owasp-top-10-for-llm-applications-2025/`). `risk_category` enum = union of both + `benign`. Write the original-label→`risk_category` mapping table into `data_card.md`. Not a sample source.

## 5. Near-duplicate sample pairs (Step 3, ≥10% of unified)

Two clearly-labeled classes; topped up via templates if under 10% (tracked in `build_report.py`):

- **Surface-suspicious-but-benign** (`is_malicious=false`, `confidence=high`, `notes="constructed benign lookalike"`): `cat .env` for local debug, `curl https://pypi.org/...` for a dependency, `grep -r password ./src` for secret cleanup, `ssh root@db-host` legit admin, `tar -xzf backup.tgz`, `find / -name x`.
- **Surface-normal-but-malicious precursors** (`is_malicious=false` + `attack_stage_precursor=true`, `attack_family=recon_precursor`, `confidence=medium`, `notes="precursor step; not independently malicious"`): `whoami;id;uname -a`, `ls -la /etc`, `curl ifconfig.me`, `env`, `ps aux`, `netstat -tlnp`. **Not** marked malicious — avoids polluting the single-turn classifier.

## 6. Dedup + split (Step 4)

**`dedup.py`**
- Embed concatenated `turns[*].raw_text` + `structured_action` text with `sentence-transformers`, default `paraphrase-multilingual-MiniLM-L12-v2` (multilingual EN+ZH; configurable via `DEDUP_EMBED_MODEL`).
- Cluster near-dups at cosine ≥ 0.92 within each `attack_family` (+ global for benign); keep one representative (prefer higher `confidence`, then deterministic id order).
- Cross-source dedup (esp. InjecAgent / BIPIA / HF injection overlap).
- **Graceful fallback**: if torch/sentence-transformers unavailable → TF-IDF/MinHash over char-n-grams (lower fidelity); method used is logged in `dedup_report.json`.
- Output `processed/unified_dedup.jsonl` + `reports/dedup_report.json` (removed per source/family).

**`split.py`**
- Stratified by `risk_category` → train/val/test_indist (80/10/10). **Only `license_status=ok`** records.
- **`test_holdout_family.jsonl`**: 3–5 `attack_family`s fully excluded from train/val — drawn **from the `license_status=ok` pool only** (since split processes no other records); chosen for (a) enough samples and (b) conceptual distinctness; candidates `reverse_shell`, `privilege_escalation`, `advbench_gcg`, `indirect_injection_multimodal` (if present). Final set + rationale logged in `data_card.md`.
- **Leakage check**: every holdout sample's max similarity to all train samples must be < 0.85; offending train samples are moved out (to val or dropped) and logged.

## 7. Synthetic generation (Step 5) — `synth_generate.py`

- **Template engine**: `action_type × target_resource × obfuscation (base64/hex/url-encode/multilingual-swap/variable-concat/newline-inject/case-mix/unicode-homoglyph) × phrasing (imperative/polite/role-play/embedded-in-doc)` → structured events → (if LLM available) natural-language rewrite, else template strings. ~few hundred this session.
- **Red-team LLM interface** (pluggable, **dry-run mode this session** — no key present): `RedTeamClient.from_env(LLM_BASE_URL/LLM_API_KEY/LLM_MODEL)`; absent → `DryRunRedTeamClient` returns templated perturbations of existing malicious samples and logs `"dry-run: no LLM key"`. Method `rewrite_to_bypass(sample, current_rules) -> candidates`. Live red-team samples flagged pending-key in `data_card.md`/`coverage_gaps.md`.
- Output: `synthetic/synthetic.jsonl` + `synthetic/redteam_candidates.jsonl` (dry-run). Merged into `unified.jsonl` flagged `source_dataset=synthetic_template`/`synthetic_redteam_dryrun` so splits include them; artifacts also kept in `synthetic/`.

## 8. Reports (Step 6) — `build_report.py`

- **`data_card.md`**: per-source count, verified license + `license_status`, original-label→`risk_category` mapping table, known limits, `license_status` breakdown. Full-dataset distributions (`risk_category`/`attack_family`/`instruction_origin`) as markdown tables + matplotlib PNGs in `reports/figures/`. Benign-vs-malicious ratio; near-dup-pair % and precursor %; per-split sizes + distributions.
- **`coverage_gaps.md`**: languages (EN-heavy, ZH-limited), modalities (text-only unless BIPIA vision present), tool types missing, **JailbreakBench/AdvBench domain gap** (general content-safety vs Agent action-risk; ablation recommended), no live red-team LLM samples (pending key), sources skipped (network/rate-limit/ToU), license-pending sources held out, GTFOBins/LOLBAS command-pattern-only limitation.
- **`fetch_manifest.json`** (user-requested): per-source `fetched_at` timestamp + `source_ref` (commit/revision) + n_samples + status → drives **incremental refresh** decisions for evolving rule libraries (ClawSentry/LlamaFirewall), so the dataset is not frozen after one pull. README documents the incremental-refresh procedure.

## 9. Failure handling & constraint compliance

- Every fetch in try/except: on failure log to `reports/fetch_errors.log` + `coverage_gaps.md` and **skip** — never bypass access limits (rate limits, auth, ToU gates).
- License gate via `license_status` + `license_config.yaml` allowlist; conservative default holds out all unknown/custom/no-license sources; GPL-3.0 noted (copyleft) but usable for metadata extraction.
- Reproducibility: pinned `requirements.txt`, `source_ref` per record, `run_pipeline.py --sources X` resume, `Makefile`, `README` reproduce steps, `fetch_manifest.json` for incremental updates.
- **No complete payloads**: GTFOBins/LOLBAS/MITRE/synth produce command *patterns*/classifier samples, not working exploit chains.
- **Local-only**: all fetches from public repos/HF into local `raw/`; no third-party live systems (defensive-tool context).

## 10. v0 done-bar (this session)

- [ ] `dataset/` repo with venv + pinned `requirements.txt` + README/Makefile.
- [ ] All `fetch_*.py` / `normalize_*.py` scripts; `merge_unified.py`, `dedup.py`, `split.py`, `synth_generate.py`, `build_report.py`, `run_pipeline.py`.
- [ ] `raw/` populated for every reachable source; failures logged+skipped.
- [ ] `processed/unified.jsonl` (+ `per_source/` slices) populated; `license_status` applied.
- [ ] `train/val/test_indist/test_holdout_family` written; holdout leakage-checked.
- [ ] `synthetic/` small-scale output; red-team interface in dry-run.
- [ ] `data_card.md`, `coverage_gaps.md`, `fetch_manifest.json`, distribution PNGs.
- [ ] Spec committed; pipeline re-runnable end-to-end.

## 11. Open items / future work

- Legal confirmation of `needs_confirmation` sources → flip in `license_config.yaml`.
- Live red-team LLM run (once an endpoint/key is provided) → the interface is ready.
- Per-source ablation of JailbreakBench/AdvBench for the Agent scenario.
- Incremental refresh cadence per source (from `fetch_manifest.json`).
- Multilingual (ZH) and true multimodal (vision) coverage — currently gaps.
