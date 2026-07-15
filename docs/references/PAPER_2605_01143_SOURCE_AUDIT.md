# arXiv:2605.01143 Source Audit

> Paper: <https://arxiv.org/abs/2605.01143>  
> Retrieval: 2026-07-15  
> Fixed paper version: `2605.01143v2`, submitted 2026-07-10  
> Earlier version checked: `2605.01143v1`, submitted 2026-05-01  
> Official code: <https://github.com/Yunicorn228/A-Low-Latency-Fraud-Detection>  
> Fixed code commit: `acd51089d05cc13fcb29644170db764a94d936f6`

The current paper is *A Fraud-Detection-Inspired Framework for LLM Agents Security*, by Sheldon Yu, Yingcheng Sun, Hanqing Guo, and Qianqian Tong. The arXiv record is a preprint; the PDF still contains the unfilled ACM conference template (`Conference acronym 'XX'`, placeholder DOI, 2018 template text). No peer-reviewed publication status was established by the inspected sources.

All code paths below refer to the fixed official-code commit. “Fact” is directly supported by the paper or source, “inference” is a project interpretation, and “unknown” marks evidence not supplied by either artifact.

## 1. Version and artifact status

### v1 to v2 changes

The v1/v2 PDFs were compared directly.

| Area | v1 | v2 | Consequence |
|---|---|---|---|
| Title | *A Low-Latency Fraud Detection Layer for Detecting Adversarial Interaction Patterns in LLM-Powered Agents* | *A Fraud-Detection-Inspired Framework for LLM Agents Security* | v2 frames a general feature framework more strongly than one fixed layer |
| Authors | Sheldon Yu, Yingcheng Sun, Hanqing Guo, Julian McAuley, Qianqian Tong | Sheldon Yu, Yingcheng Sun, Hanqing Guo, Qianqian Tong | Julian McAuley was removed |
| Availability | No code link in abstract | Official GitHub link added | Exact experimental features can now be checked in source |
| Fifth group | `fraud` / fraud-inspired | `trajectory` | Terminology changed; experiment code still uses `fraud` internally |
| Feature commitment | Fixed 42-feature implementation is foregrounded | Five groups are “one concrete instantiation,” not exhaustive or fixed | A project need not reproduce all 42 to use the hypothesis, but must not call a different vector a reproduction |
| Model choice | XGBoost foregrounded | Explicitly one lightweight instantiation; shallow neural networks are compatible | The paper does not mandate XGBoost |

The principal Table 3 and Table 4 numbers remain materially unchanged. The official code repository has one visible commit dated 2026-05-01, still uses the v1 title/terminology, and predates v2. It has no release/tag and no LICENSE file. It contains generator and experiment source but no committed generated 12,000-session dataset, trained model, or result-output directory. Thus “Code, models, and more details” in v2 and “Code and data” in the code README overstate what is actually committed.

## 2. Detector placement and formal object

**Paper fact.** The detector is placed after an Agent proposes an action and before a critical tool/high-impact action executes. It may also run after a context update. Section 3.2 defines:

```text
S_1:T = {(x_1, a_1), ..., (x_T, a_T)}
r_t = f(g(S_1:t))
```

- `x_t` is model-visible input, including user input or content added to context;
- `a_t` is the Agent's proposed action;
- `S_1:t` is the observable prefix through the current turn;
- `g` creates structured features and `f` assigns a risk score.

Section 3.5 maps the score to `allow`, `restrict`, or `block` thresholds. This is a defensive pre-execution formulation in the paper.

**Project inference.** For an attacker-oriented Eval/Fuzzing engine, `g(S_1:t)` is useful after adaptation as campaign feedback, novelty scoring, case prioritization, or a comparative baseline. The paper's online threshold decision is not evidence that the score can determine exploit effect or final security adjudication.

## 3. The experimental 42 features

The paper states the five group dimensions (`11/8/6/6/11`) but does not provide a 42-row definition table. The exact list comes from `agent_fraud/config.py::FEATURE_GROUPS` and `agent_fraud/fraud_features.py::FRAUD_FEATURE_COLUMNS`.

| Group | Count | Exact official-code columns |
|---|---:|---|
| Prompt | 11 | `turn_index`, `current_prompt_len`, `current_external_len`, `current_token_count`, `current_prompt_entropy`, `current_override_hits`, `current_secret_hits`, `current_action_hits`, `current_probe_hits`, `current_rule_score`, `prompt_filter_block` |
| Session | 8 | `retry_count`, `repeated_request_ratio`, `denied_action_count`, `recent_untrusted_turns`, `probe_turn_ratio`, `semantic_drift`, `tool_switch_count`, `distinct_tool_count_so_far` |
| Tool | 6 | `task_tool_mismatch`, `proposed_tool_web_fetch`, `proposed_tool_summarize`, `proposed_tool_read_local_file`, `proposed_tool_send_email`, `proposed_tool_run_shell` |
| Context | 6 | `external_override_hits`, `external_secret_hits`, `external_action_hits`, `suspicious_external_flag`, `untrusted_external_flag`, `follows_recent_retrieval` |
| Trajectory (`fraud` in code) | 11 | `cumulative_tool_risk`, `tool_risk_delta`, `tool_risk_monotone_flag`, `distinct_tool_ratio`, `sensitive_read_count_so_far`, `external_recipient_count`, `sensitive_read_then_send`, `recipient_novelty_flag`, `file_novelty_flag`, `action_burst_score`, `context_exfil_gap` |

Base feature formulas are in `agent_fraud/features.py::build_prefix_dataframe`; rule inputs come from `agent_fraud/rule_filter.py::compute_rule_score`; trajectory formulas are in `agent_fraud/fraud_features.py::annotate_prefix_df_with_fraud_features`.

### Key trajectory definitions in source

| Feature | Actual code definition at prefix `t` | Required source fields |
|---|---|---|
| `cumulative_tool_risk` | Sum of the fixed risk value for proposed tools observed through `t` | Exact proposed tool per turn and risk map |
| `tool_risk_delta` | Current tool risk minus previous turn's tool risk | Ordered proposed tools |
| `tool_risk_monotone_flag` | `1` if all risk values so far are non-decreasing; vacuously `1` on the first turn | Ordered proposed tools |
| `distinct_tool_ratio` | Distinct proposed-tool count divided by turns observed | Exact proposed tool identity |
| `sensitive_read_count_so_far` | Count of sensitive `read_local_file` events strictly before the current emitted row | Tool name, argument, sensitive-target classifier |
| `external_recipient_count` | Count of earlier `send_email` recipients outside the benign training profile | Tool arguments and training-only benign recipient set |
| `sensitive_read_then_send` | Current tool is `send_email` and at least one prior sensitive read exists | Cross-turn tool/argument lineage proxy |
| `recipient_novelty_flag` | Current email argument is absent from a benign-only training profile | Current arguments and fitted benign profile |
| `file_novelty_flag` | Current read path is absent from the benign-only training profile | Current arguments and fitted benign profile |
| `action_burst_score` | Fraction of the last three tool risks with value at least 2 | Ordered proposed tools and risk map |
| `context_exfil_gap` | Turn-index difference from first prior sensitive read to a current `send_email`; otherwise 0 | Ordered read/send events |

`agent_fraud/fraud_features.py::fit_benign_profile` fits recipient/file novelty sets only on benign training sessions. This avoids direct test-set look-ahead, but the feature's usefulness remains dependent on a representative and uncontaminated benign profile.

## 4. Attack families and synthetic data

Table 2 and `agent_fraud/config_session_fragile.py` define four attacks:

| Family | Turns | Constructed pattern |
|---|---:|---|
| `split_exfil` | 2 | Sensitive read, then external email |
| `context_laundering` | 4 | Two benign fetches, sensitive read, then external email |
| `privilege_drift` | 4 | Monotone escalation from fetch through reads to external email |
| `staged_burst` | 3 | Two adjacent sensitive reads, then one external email |

**Paper fact.** The large experiment generates 12,000 balanced synthetic sessions: 6,000 benign and 6,000 attack. It uses a fixed-seed 60/20/20 train/validation/test split, giving a 2,400-session held-out test set (1,200 benign, 1,200 attack) and roughly 6,000 test-prefix instances.

**Source fact.** `experiments/session_fragile.py::_SessionFragileGenerator.generate` splits each class and samples from parameterized, split-assigned templates; `agent_fraud/config_session_fragile.py` provides shared prompt pools and session structures. Half of benign sessions in this experiment are hard-benign (`SF_HARD_BENIGN_RATIO = 0.5`). The general generator separately uses 0.35, so the latter must not be attributed to the paper's session-fragile run.

The committed README distinguishes two runs:

- headline Table 3/Figure 4: 1,000 sessions (`500 + 500`) with Qwen3-4B baselines;
- Table 4/Figure 5 ablation: 12,000 sessions (`6,000 + 6,000`) with the structured detector.

The paper says it generates 12,000 interactions and later says the canonical comparison uses 500 samples while larger validation uses 1,000, but it does not clearly reconcile the two run sizes with Table 3 or explain why the full-model values differ between Table 3 (`AUC .97`, `F1 .76`, ASR reduction `.92`) and Table 4 (`AUC .96`, `F1 .81`, ASR reduction `.94`). The code README is more explicit than the paper here.

## 5. Prefix labels: a material paper/source mismatch

**Paper fact.** Section 4.1 says each prefix `S_1:t` is adversarial if its corresponding interaction *ultimately* reaches an unsafe execution event. Read literally, an early benign-looking prefix can receive a positive label because of a future turn.

**Source fact.** The actual experiment first builds current/past-only labels and then calls `experiments/session_fragile.py::_relabel_prefixes_sensitive_to_session`. The base `agent_fraud/features.py::_derive_prefix_label` labels current prompt/external risk or current execution-like risk, with onset handling for multi-turn/composite cases. The relabeler uses sensitive material already observed in the prefix and labels the exfil/privileged-execution turn, rather than marking every earlier prefix from a session that later becomes unsafe.

**Impact.** Paper prose and official implementation define different supervised targets. The code path is less obviously future-leaking than the prose, but a reproduction must name which target it uses. Neither target is equivalent to this project's desired separation of:

- attack attempt or influence;
- Agent decision/proposed action;
- objective authorization/policy violation;
- guardrail/security-control effect;
- verified environmental exploit effect.

The paper collapses these into an adversarial-prefix label and a policy simulation. That label must not become human gold truth for a general Eval/Fuzzing engine.

## 6. Model, thresholds, baselines, and latency

### Structured model

`agent_fraud/models.py::train_structured_detector` selects XGBoost only when `AGENT_FRAUD_ENABLE_XGBOOST=1`; otherwise it falls back to scikit-learn `GradientBoostingClassifier`, including on import or fit failure. `scripts/run_session_fragile.sh` enables XGBoost for the published run.

The XGBoost configuration is:

- `n_estimators=180`;
- `max_depth=4`;
- `learning_rate=0.08`;
- `subsample=0.9`;
- `colsample_bytree=0.9`;
- `eval_metric="logloss"`;
- `random_state=42`;
- `n_jobs=1`.

Thresholds are calibrated on validation prefixes in `agent_fraud/evaluation.py::calibrate_policy_thresholds`; test policy results are computed separately.

### Main reported results

| Detector | AUC | Precision | Recall | F1 | ASR reduction | p50 latency/prefix |
|---|---:|---:|---:|---:|---:|---:|
| Rule filter | .63 | 1.00 | .25 | .40 | .68 | .4 ms |
| Prompt-only | .85 | 1.00 | .15 | .26 | .15 | 43.0 ms |
| Single-step | .85 | 1.00 | .15 | .26 | .15 | 42.9 ms |
| Seq-window | .94 | .99 | .55 | .71 | .77 | 43.1 ms |
| Structured (“Ours”) | .97 | .90 | .66 | .76 | .92 | 4.6 ms |

The three text baselines use Qwen3-4B on an NVIDIA RTX A6000. The structured model is reported on a single CPU thread, but the CPU model and full host configuration are unspecified. This prevents treating 4.6 ms as a portable latency promise.

Table 4 reports the 12,000-session ablation. Trajectory-only reaches `AUC .91 / F1 .76 / ASR reduction .87`; the full vector reaches `.96 / .81 / .94`. These values show strong lift under the synthetic template construction, not arbitrary-Agent effectiveness.

## 7. What the paper proves and does not prove

### Supported by its experiment

- Structured current/prefix features can separate the authors' four synthetic trajectory families from their paired benign templates.
- Cross-turn trajectory features provide most of the measured lift in that controlled corpus.
- A small tabular model can be much cheaper than the chosen Qwen3-4B embedding baselines under the reported hardware and harness.
- Prefix-based scoring and benign-profile novelty are plausible candidates for early/running feedback.

### Not established

- Generalization to arbitrary Agents, tool schemas, real permissions, real tool failures, or real indirect-injection environments.
- Correct attribution of attack influence, authorization, policy violation, guardrail effect, or objective environmental harm.
- Deterministic confirmation of data lineage or exploit effect.
- Superiority on naturally distributed data; the corpus is balanced rather than fraud-like imbalanced.
- Robustness to an adaptive attacker who sees the score or reverse-engineers the fixed patterns.
- A requirement to use 42 particular features, XGBoost, or the score as final adjudication.
- The stated latency on other CPUs, runtimes, feature sources, or production telemetry.

## 8. Leakage and generalization risks

| Risk | Evidence | Assessment |
|---|---|---|
| Future-label ambiguity | Paper's “ultimately leads” prefix definition differs from source's onset/current-risk relabeling | P1 documentation/source mismatch; reproduce source and label semantics separately |
| Template regularity | Four handcrafted structures, shared prompt pools, split-assigned parameterized templates | Model can learn generator structure rather than general Agent security behavior |
| Tool-space closure | Fixed tools such as `web_fetch`, `summarize`, `read_local_file`, `send_email`, `run_shell` | Tool one-hots and risk paths do not transfer automatically |
| Feature-target coupling | `sensitive_read_then_send`, burst, monotonicity, and gap directly encode the four designed families | Strong ablation performance is partly by construction |
| Benign-profile dependence | Novelty is fitted from known benign recipients/files | Deployment/campaign drift and poisoned profiles can reverse meaning |
| Artifact incompleteness | No generated corpus, trained model, outputs, license, or environment lock committed | Full independent reproduction and lawful reuse remain unverified |

## 9. Mapping to the current project

The project's independent mapping at `reports/tier1_paper_feature_mapping_audit.md` checked the fixed official code against `tier1/features.py` and model metadata. It found:

- official vector: 42 dimensions (`11/8/6/6/11`);
- project Tier1: 40 dimensions (`11/8/6/6/9`);
- exact matches: **0**;
- approximate proxies: **32**;
- missing official signals: **10**.

The local features often use full-prefix text proxies where the official feature requires the current proposed tool, external input, tool argument, denial result, or a training-only benign profile. Consequently, current local Tier1 results are not a reproduction of the paper and cannot support paper-compatible feature-group ablations.

For a future general Eval/Fuzzing interface, the following official signals require fields not reliably present in the current text-oriented records: exact proposed tool and argument, tool outcome/denial, external-content direction, current-vs-history boundaries, sensitive-target classification, recipient/file identity, and an uncontaminated training/reference profile. Missing fields must remain missing; text inference is a proxy, not equivalent observation.

## 10. Project disposition

- **ADOPT:** the hypothesis that attacks should be evaluated over prefixes/trajectories, and that novelty, escalation, burst, and cross-action patterns are useful named signals.
- **ADAPT:** compute such features over normalized, actually observed Target events and use them as attack-mutation feedback, prioritization, or candidate grader/routing inputs.
- **EXPERIMENT:** the exact 42-feature vector, benign-profile novelty, XGBoost, thresholds, and transfer to arbitrary Agents. These require project-data baselines and ablations.
- **REJECT:** “the architecture must use XGBoost,” “42 features are the final contract,” or “the adversarial-prefix label is the final safety verdict.”
- **UNKNOWN:** whether the authors will publish the generated corpus/models, add a license, or update code to v2 semantics.

**Recommended role:** candidate lightweight feedback scorer and independent trajectory baseline—not the outer fuzzing architecture and not the final exploit-effect adjudicator.

## 11. Documentation/source findings

| Severity | Claim | Source fact | Disposition |
|---|---|---|---|
| P1 | Paper labels every prefix by whether the interaction ultimately becomes unsafe | Official code labels based on current/onset and already-observed prefix signals | Treat as two different targets; do not silently conflate them |
| P1 | “Code, models” / repository “Code and data” | No generated dataset, trained artifact, or result output is committed | Availability statement is overbroad |
| P1 | Paper presents 12,000 interactions without clearly separating headline and ablation runs | Code README says Table 3 uses 1,000 sessions and Table 4 uses 12,000 | Record per-table provenance before comparing numbers |
| P2 | Paper gives a 42-feature framework | Paper enumerates groups/concepts, not all 42 names; exact vector comes from code | Cite both paper and pinned source |
| P2 | v2 terminology is current | Official code still uses the v1 title and `fraud` group | Pin artifacts independently |
| P2 | 4.6 ms on a CPU thread | CPU model/system is not reported | Do not turn this into a project latency target |

