# ClawSentry Source Audit

> Repository: <https://github.com/Elroyper/ClawSentry>  
> Retrieval: 2026-07-15  
> Default branch: `main`  
> Fixed commit: `b5fe3a764e10e78f7fd5799cb9438896cdb60096`  
> Latest release checked: `v0.8.6` at `2a3a826bb731cb18db88f84be9a6dd3974a321f9`

All source paths and symbols below refer to the fixed commit unless stated otherwise. “Fact” is directly implemented; “inference” is a project interpretation; “unknown” means the inspected source did not establish the claim.

## 1. Version warning

Current `main` is `v0.8.6-2-gb5fe3a7`, but the two post-tag commits are not a small patch in tree terms: `git diff v0.8.6..b5fe3a7` reports **218 files, 118,810 insertions, 28,055 deletions**. The commits add/fix serialized-output injection detection and contamination-driven L2 routing while also landing a large module reorganization. Any source-level reuse must pin `b5fe3a7`; the PyPI/release tag is not an equivalent baseline.

## 2. Accurate positioning and adapters

**Fact.** ClawSentry is an AHP supervision Gateway/sidecar for runtime Agent frameworks. It normalizes host events, evaluates policy, returns a canonical decision, and persists an audit trail. Evidence: `src/clawsentry/gateway/core/supervision_gateway.py::SupervisionGateway`, `src/clawsentry/gateway/core/sync_decision_flow.py::handle_sync_decision`, and `src/clawsentry/gateway/models.py`.

Supported integration surfaces found in source:

| Framework | Source | Actual boundary |
|---|---|---|
| a3s-code | `adapters/a3s_adapter.py`, `adapters/a3s_gateway_harness.py` | Explicit SDK/AHP transport; strongest protocol parity |
| Claude Code | `cli/initializers/claude_code.py`, harness adapter | Host hooks; enforcement depends on installed host configuration |
| Codex CLI | `adapters/codex_adapter.py`, `cli/initializers/codex.py` | Session watcher plus managed synchronous `PreToolUse` and `PermissionRequest` for Bash and `apply_patch|Edit|Write|mcp__.*`; other lifecycle hooks are observation-oriented |
| Gemini CLI | `adapters/gemini_adapter.py`, Gemini initializer | Native hooks; shell actions are normalized; host harness startup failure is intentionally fail-open |
| Kimi CLI | `adapters/kimi_adapter.py`, Kimi initializer | Native `[[hooks]]`; allow/block and prompt deny exist, but native modify/defer parity does not |
| OpenClaw | `adapters/openclaw_adapter.py`, `openclaw_normalizer.py` | WebSocket approval plus webhook observation; setup is host dependent |

**Inference.** Adapter support is not a binary “supported/not supported” field. An Eval engine borrowing this model needs a capability matrix for observation, pre-action control, post-action evidence, tool-argument fidelity, and decision-effect parity.

## 3. Canonical event and decision contracts

### CanonicalEvent

`src/clawsentry/gateway/models.py::CanonicalEvent` and its enums define:

- event kinds: `PRE_ACTION`, `POST_ACTION`, `PRE_PROMPT`, `POST_RESPONSE`, `ERROR`, `SESSION`;
- required identity/time fields: schema version, event ID, trace ID, session ID, Agent ID, source framework, timestamp, payload;
- optional correlation and normalization fields: parent ID, depth, tool name, risk hints, framework metadata, subtype, run/approval IDs, source sequence/protocol/mapping profile.

### CanonicalDecision

`src/clawsentry/gateway/models.py::CanonicalDecision` defines the stable verdict set `ALLOW`, `BLOCK`, `MODIFY`, `DEFER`, plus reason, policy ID/version, risk, decision source, latency, modified payload, decision effects, scope evaluation, retry/failure state, and finality.

`RiskDimensions` names D1 tool danger, D2 target sensitivity, D3 command danger, D4 context/session accumulation, D5 trust, and D6 injection. `RiskSnapshot` preserves the immutable dimensions, classification tier, rule hits, L2/L3 summary, effect and taint summaries, authority class, and contextual clearance.

**Project use: ADAPT.** The event/effect vocabulary is valuable for normalized observations and deterministic assertions. Gateway request deadlines, approval IDs, and online verdict effects are runtime-specific and should not define the outer Eval/Fuzzing artifact.

## 4. Gateway and conditional control flow

**Fact.** `SupervisionGateway` owns the policy engine, trajectory/session stores, post-action and trajectory analyzers, defer handling, budgets, metrics, and audit/event publication.

`handle_sync_decision` performs validation/deadline handling, context enrichment, pre-action evidence collection, session/anti-bypass/budget routing, policy evaluation, trajectory matching, persistence, and audit publication. Decisions are persisted before a deadline error is returned; the deadline error carries the computed fallback decision (`sync_decision_flow.py::handle_sync_decision`, deadline branch).

**Fact.** This is a **conditionally invoked layered system**, not a pipeline in which every event always traverses L1, L2, and L3:

- L1 runs for policy-evaluated events.
- L2 runs only when requested, required by a contextual route, forced by contamination, or selected by an automatic route (`policy/engine.py::PolicyEngine.evaluate`, `_should_run_l2`).
- Within the nested semantic analyzer, a decisive high-risk L2 result can skip L3 (`analysis/semantic_analyzer.py::CompositeAnalyzer.analyze`).
- L3 can be forced by an explicit/deeper contextual route, L2 uncertainty, an eager profile, a suspicious sequence, cumulative risk, or a high-risk complex payload (`l3/trigger.py::L3TriggerPolicy`).
- Observation events do not run the same blocking path as a pre-action (`policy/engine.py::PolicyEngine.evaluate`).

This answers the first key question: ClawSentry exposes three named decision tiers, but the runtime is a routed graph with shortcuts, not a fixed three-stage conveyor belt.

## 5. Pre-action versus post-action

**Fact.** Post-action/post-response/error/session events are observation-oriented and ordinarily receive `allow`; they cannot retroactively stop an action that already completed. Source: `gateway/policy/engine.py::PolicyEngine.evaluate` and `_decide`.

**Fact.** `analysis/post_action_analyzer.py::PostActionAnalyzer.analyze` examines up to 64 KiB of output for:

- indirect injection;
- exfiltration;
- secret exposure;
- obfuscation.

It returns `log_only`, `monitor`, `escalate`, or `emergency`, with severity floors for concrete exfiltration/secrets/injection. `SupervisionGateway._run_post_action_async` records the finding, marks session contamination, publishes alerts, and can install session defer/block enforcement. `PolicyEngine.evaluate` can use contamination to upgrade the next or all later pre-actions to L2.

**Inference.** For offline Eval, these detectors are useful assertion candidates (“did output contain a verified secret/exfil pattern?”). The contamination and future-session enforcement mechanism is runtime-specific.

## 6. L1: real responsibility and D1-D6

The principal implementation is `src/clawsentry/gateway/analysis/risk_snapshot.py::compute_risk_snapshot`.

| Dimension | Source symbol | Implemented meaning |
|---|---|---|
| D1 | `_score_d1` | Tool/action danger |
| D2 | `_score_d2` plus normalized effects | Target/path/resource sensitivity |
| D3 | `_score_d3` | Known dangerous/destructive command patterns |
| D4 | `SessionRiskTracker` | High-risk count, burst, repetition, rate, and post-action contamination |
| D5 | `_score_d5` | Agent trust |
| D6 | `analysis/injection_detector.py::score_layer1` | NFKC/regex/invisible-character/external-content injection signals |

L1 also normalizes effects and taint, applies short-circuits, and computes a composite risk/route. These are deterministic or bounded heuristics suitable for conversion into named assertions, provided the Eval engine keeps “pattern matched” separate from “exploit effect confirmed.”

## 7. L2: trigger, analyzers, and context

`analysis/semantic_analyzer.py` defines `SemanticAnalyzer`/`L2Result` and provides:

- `RuleBasedAnalyzer`;
- `LLMAnalyzer`;
- `CompositeAnalyzer`.

The L2 evidence capsule includes L1 dimensions/rule hits, normalized effects, taint, skill/session/MCP summaries, content evidence, and a delimited/redacted payload. Ordinary L2 failures fall back to L1; contextual-review failures take a fail-closed branch (`policy/engine.py::_run_l2_analysis` and exception handling).

**Fact.** L2 is not synonymous with “one LLM call”: it is a protocol with rule, LLM, and composite implementations.

## 8. L3: existence, trigger, tools, and limits

**Fact.** L3 is implemented and can affect synchronous decisions.

- `analysis/agent_analyzer.py::AgentAnalyzer` implements a multi-turn LLM review Agent, with legacy single-turn fallback.
- Its whitelist includes trajectory/page, file/range, transcript, session risk, L3 trace, code search, Git diff/status/show, changed files, package manifest, and directory listing.
- `review/toolkit.py::ReadOnlyToolkit` confines paths to a workspace, caps file/trajectory/search sizes, and enforces a maximum of 20 tool calls.
- `AgentAnalyzerConfig` defaults to at most eight reasoning turns and applies provider/token/time budgets.
- `l3/trigger.py::L3TriggerPolicy` implements conditional triggers; `llm/factory.py` composes `[RuleBasedAnalyzer, LLMAnalyzer]` with `AgentAnalyzer` when enabled.

**Similarity to a candidate deep investigation Agent:** multi-turn reasoning, explicit read-only tools, bounded workspace, trajectory/code/Git evidence, and honest budget/error traces.

**Difference:** ClawSentry's L3 is embedded in a live Gateway, reasons around one pending decision and session, and merges back into a runtime risk/verdict. A future Eval investigator would operate over a frozen campaign artifact, deterministic oracle evidence, and explicit attacker/grader visibility boundaries.

## 9. Do L1/L2/L3 and trajectories affect the final decision?

**Fact.** Yes, with qualifications:

- L1 is the base snapshot and decision.
- L2/L3 results selected by `CompositeAnalyzer` update the snapshot; ordinary results are bounded by `max(result risk, L1 risk)` in `PolicyEngine._run_l2_analysis`.
- Contextual review can explicitly clear a bounded route to `MEDIUM` and `allow`; confirmed bounded read-only session scope can also relax a prior `block/defer` to `allow` (`PolicyEngine._apply_session_scope`).
- Deterministic hard blocks remain protected by earlier branches.
- The dedicated trajectory analyzer runs after base policy evaluation and can override a pre-action to configured `defer` or `block`; it refuses to weaken an existing block (`sync_decision_flow.py`, trajectory analysis branch).

Therefore the inner README's blanket “L2/L3 can only raise risk, never lower it” is false at current `main`. Ordinary merge is upgrade-only, but contextual clearance and bounded read-only scope are explicit downgrade/relaxation paths.

## 10. Where trajectory analysis lives

Trajectory detection spans multiple components:

1. L1 D4 accumulates session risk.
2. `analysis/trajectory_analyzer.py::TrajectoryAnalyzer` maintains a bounded per-session ring buffer and implements five built-ins:
   - `exfil-credential`;
   - `backdoor-install`;
   - `recon-then-exploit`;
   - `secret-harvest`;
   - `staged-exfil`.
3. `L3TriggerPolicy` separately recognizes suspicious sequences such as secret-plus-network, privilege escalation chains, temp staging/exfil, recon-then-sudo, and secret-harvest/archive.
4. L3 can query the trajectory through the read-only toolkit.

This answers the second key question: trajectory analysis is neither “an L1 feature” nor “an L3 feature” alone; it is distributed across L1 accumulation, a dedicated decision-affecting matcher, L3 routing, and L3 evidence access.

## 11. Failure, timeout, and budget behavior

`policy/engine.py::make_fallback_decision` implements Gateway-unavailable fallback:

- high-danger pre-action: `block`/fail closed;
- other pre-action: `defer`;
- pre-prompt and observation events: `allow`/fail open.

LLM budget exhaustion forces L1 and records the reason. L2/L3 analyzer failure normally degrades to L1; contextual routes fail closed. Deadline overruns return a retryable error carrying the already persisted decision. L3 tool/turn/provider failures are represented in trace/accounting instead of being reported as completed review.

## 12. Evidence Resolver comparison

**Fact.** No standalone horizontal service equivalent to the project's PDF “Evidence Resolver” was found.

Closest facilities are:

- `ReadOnlyToolkit`, available to L3;
- pre-decision context/content enrichment;
- trajectory and session stores;
- effect, taint, asset, and session-scope normalization.

**Unknown.** These could be refactored into a general evidence service, but current source does not establish such a service shared horizontally by every analyzer/reconstructor.

## 13. Runtime-only versus Eval-reusable capabilities

| Reusable/adaptable for offline Eval | Runtime-Gateway-specific |
|---|---|
| Canonical event/effect vocabulary | Live `allow/block/modify/defer` enforcement |
| Tool/path/command/secret/injection patterns | Approval bridge and host response encoding |
| Five trajectory matchers and session signal concepts | Quarantine/session enforcement |
| Pre-action/post-action distinction | Deadline/latency/fallback SLA behavior |
| Adapter capability-matrix semantics | UDS/HTTP/WS transports and host setup |
| Versioned reason/evidence/audit fields | Contamination changing later live actions |

## 14. README/source differences

| Severity | Documentation claim | Source fact | Disposition |
|---|---|---|---|
| P1 | `src/clawsentry/README.md`, “Escalate only”: L2/L3 never lower risk | Contextual clearance and session-scope bounded read-only relaxation can lower/allow; see `PolicyEngine._run_l2_analysis`, `_decide`, `_apply_session_scope` | Documentation is stale/overbroad |
| P1 | Inner README diagrams and introduction describe every event as passing through a three-layer pipeline | L2 and L3 are conditional; decisive L2 can skip L3; observation events take different paths | Replace “fixed pipeline” interpretation with routed layers |
| P1 | Root README says Codex managed `PreToolUse` is Bash-only | Current initializer installs synchronous `PreToolUse` for Bash **and** `apply_patch|Edit|Write|mcp__.*` | Root README is stale relative to current source; inner README matches source here |
| P2 | Root/inner architecture summaries place “trajectory analysis” under L2 or a linear L1→L2→L3 picture | Actual trajectory logic spans D4, a post-policy matcher, L3 trigger, and toolkit access | Ownership wording is misleading |
| P2 | Inner README presents itself as current release `v0.8.6` | Audited `main` is two commits ahead with a massive tree delta | Pin the commit; do not infer release parity |

## 15. Project disposition

- **ADAPT:** canonical event/effect semantics, adapter capability matrix, deterministic D1-D3/D6 patterns, post-action fact detectors, and trajectory matchers.
- **EXPERIMENT:** D4 accumulation and semantic/L3 findings as optional grader signals on our campaigns.
- **REJECT for first-version core:** online three-tier routing, approval/defer flow, and Gateway fallback as the product's outer architecture.
- **UNKNOWN:** any claim that ClawSentry already provides a general horizontal Evidence Resolver.
