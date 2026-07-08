# ClawSentry L1 reusable mechanisms

Concrete mechanisms extracted for reuse. No project summary.

## Text preprocess — `text_utils.py`
- `INVISIBLE_CODEPOINTS: frozenset[int] = _build_invisible_codepoints()` (lines 23-87): ~390 invisible cps. Ranges: U+200B-200F, U+202A-202E, U+2060-2065, U+2066-2069, U+206A-206F, U+180B-180F, Hangul fillers 0x115F/0x1160/0x3164/0xFFA0, Khmer 0x17B4/0x17B5, 0x00AD, 0x034F, 0x061C, 0xFEFF, VS 0xFE00-0xFE0E (excludes 0xFE0F to keep emoji), 0xE0001, tags 0xE0020-0xE007F, VS-sup 0xE0100-0xE01EF.
- `INVISIBLE_RE = _build_invisible_re()` (93-108): compiled char-class regex over the set.
- `normalize_text(text: str) -> str` (114-144): NFKC -> NFD, drop category Mn except keep U+FE0F -> NFC -> `INVISIBLE_RE.sub("", ...)`.
- `count_invisible_chars(text: str) -> int` (147): raw count before normalization.

## D1 tool danger (0-3) — `risk_snapshot.py`
- `_score_d1(event: CanonicalEvent) -> int` (179-213). Frozensets: `_D1_READONLY_TOOLS`(46)=0, `_D1_LIMITED_WRITE_TOOLS`(51)=1, `_D1_SYSTEM_INTERACTION_TOOLS`(55)=2, `_D1_HIGH_DANGER_TOOLS`(59)=3. `DANGEROUS_TOOLS`(64) expanded set ->3. bash/shell/terminal/command: `_has_dangerous_command_pattern(cmd)` or `_SYSTEM_PATHS` re (174) ->3 else 2. Unknown/no tool ->2.

## D2 path sensitivity (0-3) — `risk_snapshot.py`
- `_score_d2(event) -> int` (255-269). `_extract_paths`(230) reads payload keys path/file_path/file/target/destination/source + `_extract_paths_from_command`(244) (tokens starting `/`/`~`, or `/` inside non-flag token). `_D2_SYSTEM_CRITICAL`(220) ->3; `_D2_CONFIG_PATTERNS`(224, IGNORECASE) ->1; `is_credential_path(p)` or `.gnupg/` ->2. No path ->1.

## D3 command pattern (0-3) — `risk_snapshot.py`
- `_score_d3(event) -> int` (348-396), bash/shell/terminal/command/exec only; else 0. `_has_dangerous_command_pattern`(336-345): `has_remote_pipe_exec_command`, `has_process_sub_remote_command`, then `_D3_HIGH_DANGER_PATTERNS`(298-333) list ->3. First-cmd in `_D3_SAFE_COMMANDS`(276) ->0. `_D3_POTENTIAL_DESTRUCTIVE`(287)+`_D3_POTENTIAL_DESTRUCTIVE_PATTERNS`(293) ->2 (multi-word substring, single-word `\b...\b`). `_D3_REGULAR_WRITE`(282) ->1. Unknown ->2.

## D4 session accumulation (0-2) — `risk_snapshot.py`
- `class SessionRiskTracker` (403-617). `__init__(max_sessions=10000, d4_high_threshold=5, d4_mid_threshold=2, freq_enabled=True, freq_burst_count=10, freq_burst_window_s=5.0, freq_repetitive_count=20, freq_repetitive_window_s=60.0, freq_rate_limit_per_min=60)`. Per-session deques `_tool_calls[session][tool]` and `_all_calls[session]`.
- `record_high_risk_event(session_id)` (454): `_high_risk_counts[session]++`.
- `record_tool_call(session_id, tool_name, now=None, config=None)` (483): append ts, trim to repetitive window (per-tool) and 60s (all-tool).
- `_get_frequency_d4(session_id, now=None, config=None) -> int` (525): burst (same tool >=N in burst window)->2; repetitive (>=N in rep window)->1; rate (all tools >=N/min)->1.
- `get_d4(session_id, now=None, config=None) -> int` (588): accum_d4 (count>=high->2, >=mid->1, else 0); `return min(max(accum_d4, freq_d4), 2)`.
- `reset_session(session_id)` (614). `_evict_if_needed` (460) LRU bounded.

## Composite + short-circuit — `risk_snapshot.py`
- `_SHORT_CIRCUIT_RULES` (642): SC-1 (d1==3 and d2>=2 ->CRITICAL), SC-2 (d3==3 ->CRITICAL), SC-3 (d1==0 and d2==0 and d3==0 ->LOW).
- `_composite_score_v2(dims, config=None) -> float` (724): `base = w_max_d123*max(d1,d2,d3) + w_d4*d4 + w_d5*d5`; `* (1 + d6_injection_multiplier*(d6/3.0))`.
- `_score_to_risk_level_v2(score, config=None) -> RiskLevel` (744): thresholds critical/high/medium else LOW.

## L1 policy engine — `policy_engine.py`
- `L1PolicyEngine.evaluate(event, context=None, requested_tier=L1, deadline_budget_ms=None, config=None) -> tuple[CanonicalDecision, RiskSnapshot, DecisionTier]` (359-455). Calls `compute_risk_snapshot(event, context, self._session_tracker, effective_config)` (381), then `_decide`; `_should_run_l2` gates L2.
- `_decide(event, snapshot, context=None) -> CanonicalDecision` (457-722): POST_ACTION/POST_RESPONSE/ERROR/SESSION -> ALLOW; PRE_PROMPT -> ALLOW; PRE_ACTION deterministic_hard_block -> BLOCK; contextual_review_required -> BLOCK/DEFER/cleared; CRITICAL/HIGH -> BLOCK; `disabled_capability_equivalent` -> DEFER; routing intent block/defer; SC-8 (future-execution write low-trust) -> DEFER; MEDIUM -> ALLOW+audit; LOW -> ALLOW.
- `policy_priority = {"block":3,"defer":2,"audit":1}` (200), `tier_priority = {"l3":3,"l2":2,"none":1}` (201).
- `_should_run_l2(event, context, l1_snapshot, requested_tier, automatic_trigger_reason=None) -> bool` (854-866): contextual_review_required or requested_tier in (L2,L3) or automatic_trigger_reason is not None.
- SC-8 branch (669-690): `etype==PRE_ACTION and snapshot.short_circuit_rule=="SC-8"` -> DEFER.

## attack_patterns.yaml schema
Per-pattern fields: `id, category, description, risk_level, triggers{logic(AND/OR), conditions[{tool_names, file_extensions, file_patterns, command_patterns, path_patterns, OR:[...]}], tool_names, file_extensions, file_patterns}, detection{regex_patterns:[{pattern, weight}]}, false_positive_filters:[{type:"whitelist_path", paths:[glob]}], risk_escalation{from,to}, references{incidents, papers}, mitre_attack{tactics, techniques}`. 24 patterns (ASI01-001..005, ASI02-001..007, ASI03-001..005, ASI04-001..002, ASI05-001..006).

## pattern_matcher.py
- `load_patterns(path=None, *, evolved_path=None) -> list[AttackPattern]` (59): yaml.safe_load; `_parse_pattern` (141) pre-compiles detection regexes via `compile_safe_regex` into `detection["_compiled"]` as `{compiled, weight}`; pre-compiles trigger command/path patterns (`_precompile_trigger_patterns` 120). ReDoS guard `_MAX_DETECTION_INPUT_LEN=102400` (28) truncates.
- `PatternMatcher.match(tool_name, payload, content) -> list[AttackPattern]` (251): `_triggers_match`(282) -> `_detection_match`(359) -> `_is_false_positive`(398). `_eval_conditions`(333) AND/OR over `_eval_single_trigger`(294): empty trigger matches nothing; tool_names lower; file_extensions endswith; file_patterns fnmatch basename; `_compiled_command_patterns`/`_compiled_path_patterns` search.
- `_detection_match` (359): content or `payload["command"]`; truncate to 100KB; iterate `_compiled`, `max_weight = max(weight)` over fired regexes; returns `(matched, max_weight)`. NO threshold/short-circuit on score (returns all matching patterns, each tagged with max_weight).
- `_is_false_positive` (398): `whitelist_path` fnmatch on `payload["path"|"file_path"]`.
- `@dataclass AttackPattern` (37): fields incl `max_weight` populated at match time.
- `reload()` (247) hot-reload.

## Reuse map
- Step 2 (Tier 0 rule engine + text preprocess): `normalize_text`/`INVISIBLE_RE`/`INVISIBLE_CODEPOINTS` (text_utils 114/108/87); `_score_d1`(179), `_score_d2`(255), `_score_d3`(348)+`_has_dangerous_command_pattern`(336)+`_D3_HIGH_DANGER_PATTERNS`(298)+sets(276/282/287); `_SYSTEM_PATHS`(174), `_D2_SYSTEM_CRITICAL`(220), `_D2_CONFIG_PATTERNS`(224), `_extract_paths`(230); `_SHORT_CIRCUIT_RULES`(642), `_composite_score_v2`(724), `_score_to_risk_level_v2`(744); attack_patterns.yaml schema; `load_patterns`(59)+`PatternMatcher.match`(251)+`_detection_match`(359)+`_is_false_positive`(398)+`compile_safe_regex`/`_MAX_DETECTION_INPUT_LEN`(28).
- Step 4 (Tier 1 D4 session accumulation): `SessionRiskTracker` class (403); `record_high_risk_event`(454), `record_tool_call`(483), `_get_frequency_d4`(525), `get_d4`(588) combining `min(max(accum_d4, freq_d4), 2)`; `_evict_if_needed`(460), `reset_session`(614); wired via `evaluate`(381) `compute_risk_snapshot(..., self._session_tracker, ...)` and `record_high_risk_event` on L2 upgrade (policy_engine 443).
