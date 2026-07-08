# XGBoost Paper Feature Reference (arXiv:2605.01143)

Title: "A Low-Latency Fraud Detection Layer for Detecting Adversarial Interaction Patterns in LLM-Powered Agents"
Authors: Sheldon Yu, Yingcheng Sun, Hanqing Guo, Julian McAuley, Qianqian Tong (UCSD, UNC Greensboro, IU Bloomington)
Source: local PDF provided by user (full text extracted to `_xgboost_paper_raw.txt`)

## 4 Attack Families (Table 2) — for Step 3 synthetic data generation

| Family | Turns | Structure |
|---|---|---|
| split_exfil | 2 | Read sensitive file → email to external recipient |
| context_laundering | 4 | Benign fetches → sensitive read + external send |
| privilege_drift | 4 | Monotone escalation from low-risk to high-risk tool calls |
| staged_burst | 3 | Back-to-back sensitive reads → single send |

## 42 Features in 5 Groups (Section 3.3)

### Prompt Features (11) — per-turn surface signals
Per prose: prompt length, token count, suspicious keyword indicators, instruction-conflict patterns, override attempts, privilege escalation signals. Prose names 6 explicitly; the remaining 5 are sub-categories of keyword/conflict indicators. Concrete v0 implementation:
1. prompt_length (char count)
2. token_count (whitespace-split)
3. suspicious_keyword_count (matches to override/secret/action regex)
4. suspicious_keyword_max_weight
5. has_system_override (bool)
6. has_ignore_instruction (bool)
7. has_new_instruction (bool)
8. instruction_conflict_flag (bool)
9. override_attempt_flag (bool)
10. privilege_escalation_signal (bool)
11. prompt_suspicion_score (weighted sum)

### Session Features (8) — turn-indexed behavioural aggregates
Per prose: retries/repetition, denied/failed actions, recent exposure to untrusted content, semantic drift across turns, diversity in tool usage. Figure 2 adds "Sequence of Tool Transitions", "Session ID".
1. retry_count (repeated identical actions)
2. denied_tool_call_count
3. failed_tool_call_count
4. has_external_content_recently (bool)
5. semantic_drift_score (turn-to-turn embedding/keyword drift)
6. tool_diversity_score (unique tools / total calls)
7. tool_transition_count
8. session_length (turn count)

### Tool Features (6) — EXPLICIT in prose
One-hot over the discrete tool set + mismatch flag:
1. tool_web_fetch (one-hot)
2. tool_summarize (one-hot)
3. tool_read_local_file (one-hot)
4. tool_send_email (one-hot)
5. tool_run_shell (one-hot)
6. task_tool_mismatch_flag (1 if selected tool inconsistent with user request)
Total = 6 ✅ (exact)

### Context Features (6) — surrounding untrusted environment
Per prose: presence of external/untrusted content, suspicious patterns in retrieved content, sensitive resources involved, risky actions following external input.
1. has_external_content (bool)
2. suspicious_pattern_in_context (bool)
3. sensitive_resource_involved (bool)
4. risky_action_after_external_input (bool)
5. external_content_count
6. context_suspicion_score

### Fraud-inspired Features (11) — THE CRITICAL GROUP (Section 3.3, last paragraph)

**(i) Cumulative tool-risk path = 3 features:**
1. `cumulative_risk_sum` — running sum of per-turn tool-risk scores across the trajectory
2. `risk_delta` — turn-to-turn increment = current_risk - previous_risk
3. `monotonicity_flag` — 1 if cumulative risk has been monotonically non-decreasing across turns (captures privilege escalation pattern)

**(ii) Action-burst score = 1 feature:**
4. `action_burst_score` — fraction of the last 3 turns invoking a high-risk tool (captures staged-burst pattern)

**(iii) Novelty flags = 4 features** (analogous to "new device" flags in account-fraud; evaluated against a benign-only reference profile fitted on the training split):
5. `novelty_recipient_flag` — 1 if current email recipient never seen in benign training profile
6. `novelty_recipient_score` — continuous novelty/distance vs benign profile
7. `novelty_filepath_flag` — 1 if current file path never seen in benign training profile
8. `novelty_filepath_score` — continuous novelty/distance vs benign profile

**(iv) Context-exfil gap = 1 feature:**
9. `context_exfil_gap` — turn distance between the first sensitive read and a subsequent external send within the same session (captures split-exfiltration co-occurrence)

Count so far: 9. To reach 11, add 2 supplementary trajectory features:
10. `max_cumulative_risk` — peak cumulative risk across the trajectory
11. `action_burst_5` — fraction of last 5 turns invoking high-risk tool (wider burst window)
**Note: features 10-11 are inferred (paper prose explicitly defines 9; the remaining 2 to reach 11 are trajectory variants consistent with the paper's fraud-inspired definitions). Marked as design choices.**

## XGBoost Hyperparameters (Section 4.1)
- n_estimators = 180
- max_depth = 4
- Other params unspecified; v0 uses XGBoost defaults (learning_rate=0.3, subsample=1.0, colsample_bytree=1.0)

## Ablation Results (Table 4)

| Mode | Group(s) | |z| | AUC | F1 | ASR red. |
|---|---|---|---|---|---|---|
| Isolated | prompt | 11 | 0.81 | 0.57 | 0.62 |
| Isolated | session | 8 | 0.86 | 0.74 | 0.86 |
| Isolated | tool | 6 | 0.65 | 0.00 | 0.00 |
| Isolated | context | 6 | 0.67 | 0.27 | 0.33 |
| Isolated | fraud | 11 | 0.91 | 0.76 | 0.87 |
| Leave-one-out | −prompt | 31 | 0.92 | 0.75 | 0.87 |
| Leave-one-out | −session | 34 | 0.96 | 0.65 | 0.86 |
| Leave-one-out | −tool | 36 | 0.96 | 0.77 | 0.95 |
| Leave-one-out | −context | 36 | 0.96 | 0.82 | 0.97 |
| Leave-one-out | −fraud | 31 | 0.92 | 0.68 | 0.76 |
| Full | all five | 42 | 0.96 | 0.81 | 0.94 |

**Conclusion: Fraud-inspired features dominate.** In isolation they reach F1=0.76 (nearly matching full 0.81). Removing fraud causes the largest drop: F1 0.81→0.68, ASR red 0.94→0.76 (admits +18% attacks). Removing other groups is neutral or marginal. The paper explicitly states "this group alone nearly matches the full detector and dominates every other group."

## Data Generation Method (Section 4.1)
- 12,000 interactions total, split 60/20/20 (train/val/test)
- Parameterized templates simulating realistic workflows (file retrieval, email composition, web browsing, shell execution)
- Each interaction → multiple prefix evaluation points (partial histories at different turns) → ~6,000 eval instances
- Binary label: adversarial (y=1) if interaction leads to unsafe execution event (sensitive file read co-occurring with external exfiltration OR unauthorized privileged execution); benign (y=0) otherwise
- Baselines: Rule-filter (regex + count threshold 3), Prompt-only/Single-step (logistic regression on Qwen3-4B embeddings), Seq-window (rolling 3-turn Qwen3-4B)
- Latency: their XGBoost runs 4.6ms/prefix on single CPU thread; Qwen baselines ~43ms on A6000 GPU

## Reuse map
- **Step 3 (synth generator)**: 4 attack family definitions + turn structures + parameterized template approach + binary label definition + benign-control construction
- **Step 4 (Tier 1 features)**: 42-feature spec (especially Fraud-inspired 11); XGBoost n_estimators=180 max_depth=4; ablation methodology (isolated + leave-one-out)
- **Step 6 (report)**: Table 4 ablation format; baseline comparison names; latency benchmarking approach
