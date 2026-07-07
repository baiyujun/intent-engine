# Coverage Gaps — v0.1

## Source population status (post re-tuning R1–R7)
Real-backed (live-normalized, present in unified.jsonl with >0 records):
- **injecagent** (2108) — R1 JSON-array parser.
- **hf_injections** → split as `hf_deepset` (662) + `hf_jayavibhav` (4338, imoxto; needs_confirmation — held out of splits). R2 `load_from_disk`.
- **jailbreakbench** (1097) — R3 real artifact location.
- **gtfobins** (920) — R5 extensionless `_gtfobins/*` YAML.
- **agentdojo** (183) — R6 AST-parse of class-based suites.
- **clawsentry_rules** (25) — R7 mkdir fix; real `attack_patterns.yaml`.
- **lolbas** (521), **advbench** (520) — unchanged real data.

Held-out (needs_confirmation — in unified.jsonl, NOT in any split):
- **hf_jayavibhav** (imoxto, 4338), **rjudge** (571), **mitre_attack_samples** (858), **bipia**, **purplellama**, **llamafirewall_rules** (113). These require license/origin confirmation before release-grade splits include them.

Zero in unified.jsonl (fetched but produced 0 normalized records):
- **bipia**, **purplellama** — fetch ok, normalize ok, but 0 rows emitted (schema/format still mismatched or empty after filtering). See `reports/fetch_errors.log`.
- Note: `rjudge`/`llamafirewall_rules` logged AttributeError in fetch_errors but still yielded records in unified (partial).

## v0 sampling cap
- `merge_unified` caps each source to `MAX_PER_SOURCE=5000` (env) so dedup stays tractable. Only `hf_injections` hit the cap (5000 of ~5000+). A full-scale run needs scalable/batched dedup before raising this cap.

## Dedup
- Method: **TF-IDF** sparse cosine similarity, threshold 0.92. Kept sparse (densify only the n×n sim block) — memory-bounded, no OOM on the capped unified set.
- **torch / sentence-transformers embeddings are NOT installed** in this environment. The `paraphrase-multilingual-MiniLM-L12-v2` model name is recorded for future use but the actual run used TF-IDF fallback. Switching to embeddings is optional and requires installing torch.
- Input 11932 → kept 8941, removed 2991 (~25%). Largest removals: `indirect_injection` (2091, injecagent near-dups collapsed into the held `injection` family) and `lf_rule_derived` (112).

## Splits
- train 2149 / val 267 / test_indist 275 / test_holdout_family 793 (total 3484 in-dedup split records; holdout family-based).
- Holdout families: `shell_spawn`, `privilege_escalation`, `advbench_gcg` (full-family leakage isolation).
- 10 leakage offenders moved out of train/val to enforce threshold 0.85.

## Other gaps
- **Languages**: English-heavy; multilingual dedup model selected but source coverage is EN.
- **Modalities**: text-only; no audio/vision pipeline.
- **Tool types**: bounded by AgentDojo fixed suites; gaps for real-world tools/APIs.
- **Red-team LLM**: no live LLM key this run; `synthetic/redteam_candidates.jsonl` are DRY-RUN templated perturbations only.
- **GTFOBins/LOLBAS**: command patterns only — no complete payloads (by design).
- **Skipped/errored sources**: see `reports/fetch_errors.log` (rjudge, llamafirewall_rules, clawsentry_rules historical).
