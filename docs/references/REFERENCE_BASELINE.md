# Reference Baseline

> Status: source-level baseline, fixed on 2026-07-15  
> Project revision at audit start: `b48bda04e75ce8b395c1c89e3a247abcca050fb7`  
> Scope: reference facts and project crosswalk only; no product implementation is implied.

## 1. Product target used by this baseline

The current product target, confirmed by MT and restated in the task that produced this document, is an **attacker-oriented, general Agent security Eval/Fuzzing engine**. Its first-version questions are:

1. How do we actively attack an arbitrary Agent?
2. How do we observe the Agent's real tool behavior?
3. How do deterministic assertions establish whether an exploit had effect?
4. How do attack strategies mutate from target feedback?
5. How do we save, reproduce, and regress a discovered vulnerability?

This target supersedes the defensive runtime-first framing in the existing planning documents for purposes of this reference baseline. It does not silently rewrite those documents; the conflict is recorded in [REFERENCE_OPEN_QUESTIONS.md](REFERENCE_OPEN_QUESTIONS.md).

Layer 1 / Layer 2 / Evidence Resolver, online `allow/block/modify/defer`, and a defensive deep-review Agent are therefore **not the first-version overall architecture**. They remain possible grader implementations, forensic aids, or later extensions.

## 2. Locked sources

| Source | Role in this project | Fixed version used | Release relationship |
|---|---|---|---|
| [promptfoo](https://github.com/promptfoo/promptfoo) | Primary reference for orchestration, attack generation, Target integration, tracing, assertions, reporting, cache, CI, and regression | `fcde2e89a89dc4ca79dcc3012927f50193251759` (`main`, 2026-07-14) | `0.121.19-2-gfcde2e89a`; the two post-release changes are a webpack update and Goblin navigation documentation, with no scoped runtime behavior change found |
| [ClawSentry](https://github.com/Elroyper/ClawSentry) | Event normalization, tool-risk facts, deterministic patterns, and trajectory patterns convertible to assertions | `b5fe3a764e10e78f7fd5799cb9438896cdb60096` (`main`, 2026-07-11) | `v0.8.6-2-gb5fe3a7`; two commits after the tag change a very large source surface, so conclusions use `main`, not the release |
| [arXiv:2605.01143](https://arxiv.org/abs/2605.01143) | Trajectory-feature hypotheses, novelty feedback, and a candidate lightweight scorer | `v2`, 2026-07-10 | v1 (2026-05-01) was also checked; official code is fixed separately at `acd51089d05cc13fcb29644170db764a94d936f6` |

Retrieval date for all three sources: **2026-07-15**.

Local authority inputs were read from Windows Downloads because the requested `docs/source/` paths are absent:

- `项目架构方案_v1.0基线.md`, SHA-256 `eb0404f638f0112c6528e2d6f2d68d461afaaab5f61eb11dde8a0f55d9976d58`
- `Agent 安全行为评测工具设计方案_1784086737.pdf`, SHA-256 `1a344e59c5b4a49f05603013c207d99773f6a6a9a228333c4d836ea43361a618`

## 3. The sources are complementary, not alternatives

### promptfoo: the principal execution skeleton

promptfoo supplies the closest existing implementation of the desired outer loop:

```text
Purpose + Plugin/seed
        -> Strategy mutation
        -> Target execution
        -> response + optional instrumented trace
        -> Assertion/Grader
        -> persisted finding/report
        -> retry/regression/CI
```

It can run static transformations, iterative single-turn attacks, genuine adaptive multi-turn strategies, indirect-web attacks, and replay of prior failures. It can receive OpenTelemetry spans and feed a sanitized summary to compatible strategies. It does **not** create a real tool trajectory by inventing one: the Target must execute, and deeper Agent evidence must be emitted by the Target/provider or captured by a trusted sidecar.

Detailed evidence: [PROMPTFOO_SOURCE_AUDIT.md](PROMPTFOO_SOURCE_AUDIT.md).

### ClawSentry: deterministic behavior knowledge, not the outer product architecture

ClawSentry is a runtime supervision gateway. Its reusable value here is its canonical event vocabulary, action/effect normalization, deterministic D1-D6 signals, post-action findings, five concrete trajectory patterns, and explicit adapter-capability boundaries. Its live blocking, approval bridge, quarantine, latency deadline, and host-specific fallback behavior are runtime-gateway capabilities, not the first-version Eval/Fuzzing control plane.

Detailed evidence: [CLAWSENTRY_SOURCE_AUDIT.md](CLAWSENTRY_SOURCE_AUDIT.md).

### The paper: a controlled hypothesis, not an architecture mandate

The paper shows, on a balanced synthetic and template-controlled corpus, that structured cross-turn features can outperform prompt-only baselines and run more cheaply than Qwen3-4B embeddings. Its strongest reusable ideas are incremental prefix features, novelty against a benign training profile, risk-path/burst/co-occurrence features, and use of a lightweight score as feedback or routing. It neither establishes generalization to arbitrary Agents nor requires XGBoost; v2 explicitly calls XGBoost one instantiation.

Detailed evidence: [PAPER_2605_01143_SOURCE_AUDIT.md](PAPER_2605_01143_SOURCE_AUDIT.md).

## 4. Project decisions at baseline time

| Decision | Classification | Consequence |
|---|---|---|
| Use Purpose, Plugin, Strategy, Target, Assertion, report, and regression as the outer testing vocabulary | **ADOPT** | Preserve these separations in the next architecture task; do not collapse attack generation and grading into one classifier |
| Support both authored fixed sequences and adaptive multi-turn attacks | **ADOPT** | They are different case types and need different replay semantics |
| Normalize actual tool events into a framework-neutral event contract | **ADAPT** | Borrow ClawSentry semantics, but target an offline test artifact rather than its Gateway RPC envelope |
| Make deterministic exploit-effect assertions the primary security oracle where possible | **ADAPT** | Compose trace facts, controlled-environment receipts, file/network sidecars, and Target results; LLM rubrics are secondary where facts are unavailable |
| Feed traces back to an attacker | **EXPERIMENT** | Make this an explicit black-box/gray-box campaign mode; never enable it implicitly merely because tracing exists |
| Use the paper's 42 features or XGBoost as the final verdict | **EXPERIMENT** | Evaluate as novelty/routing/lightweight feedback; no mandatory model choice and no final safety authority |
| Copy ClawSentry's online three-tier decision architecture | **REJECT** for v1 core | Defensive layers may be optional graders or later forensic extensions |
| Treat a promptfoo plugin label or grader result as human gold truth | **REJECT** | These describe an attack objective or an automated test outcome, not a complete adjudicated security label |

The full capability-by-capability mapping is in [PROJECT_REFERENCE_CROSSWALK.md](PROJECT_REFERENCE_CROSSWALK.md).

## 5. Designs not directly supplied by any one source

The following are project-level compositions or additions, not capabilities that can honestly be attributed wholesale to one reference:

- A general exploit-effect oracle that combines deterministic trajectory assertions with frozen environment receipts and sidecar evidence across arbitrary Agent frameworks.
- An evidence provenance contract that distinguishes observed target behavior, attacker-visible feedback, grader-only evidence, and post-hoc forensic evidence.
- Optional physically separated Trace-only and Adjudication evidence views for forensic grading; these are not the first-version orchestration architecture.
- Fine-grained separation of attack influence, Agent decision, guardrail/security-control behavior, and objective environmental impact.
- Explicit `unknown`, `unresolved`, or harness-integrity failure when absence of evidence cannot prove safety.
- A portable vulnerability artifact containing the attack, target identity/version, environment fixture, strategy history, observations, oracle result, and replay contract.
- A policy that raw secret values may be checked by a trusted deterministic verifier but must not enter attack feedback or any LLM-facing grader representation.

## 6. Baseline conclusion

The reference evidence supports a first-version direction centered on promptfoo-like attack orchestration, instrumented Target execution, and deterministic exploit-effect assertions. ClawSentry contributes reusable observation and pattern semantics; the paper contributes experimental feature hypotheses. None of the three alone supplies the complete product.

Open facts and document conflicts are isolated in [REFERENCE_OPEN_QUESTIONS.md](REFERENCE_OPEN_QUESTIONS.md); they do not require changing product code in this phase.
