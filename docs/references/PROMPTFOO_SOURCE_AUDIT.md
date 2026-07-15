# promptfoo Source Audit

> Repository: <https://github.com/promptfoo/promptfoo>  
> Retrieval: 2026-07-15  
> Default branch: `main`  
> Fixed commit: `fcde2e89a89dc4ca79dcc3012927f50193251759`  
> Latest release checked: `0.121.19` at `1ede17aaed940e6dff04f71d24e4ecc011809dae`

Current `main` is `0.121.19-2-gfcde2e89a`. The post-release diff is four files and contains a webpack dependency update plus Goblin documentation navigation; no scoped red-team/tracing/assertion behavior change was found. All paths and symbols below refer to the fixed commit.

## 1. Core concepts in source

| Concept | Source contract | Actual role |
|---|---|---|
| Target | `targets` is normalized to `providers` by `src/util/config/load.ts::readConfig` | The system under test; can be a built-in provider, HTTP endpoint, custom script/function, Agent SDK, MCP, etc. |
| Provider | `src/types/providers.ts::ApiProvider`, `ProviderOptions`; `src/contracts/providers.ts::ProviderResponse` | Uniform `callApi` interface. A red-team generation/grading provider is distinct from the Target provider. |
| Purpose | `src/validators/redteam.ts::RedteamConfigSchema`, plugin templates | Natural-language description used to tailor generation and grading; not an authorization oracle by itself. |
| Plugin | `src/redteam/plugins/base.ts::RedteamPluginBase`, plugin registry | Defines what risk to test and generates base cases plus assertions. |
| Strategy | `src/redteam/strategies/types.ts::Strategy`, strategy registry | Transforms or adaptively executes plugin cases: how to attack. |
| Grader / Assertion | `RedteamGraderBase`, `src/assertions/index.ts`, `GradingResult` | Produces `pass`, `score`, `reason`, optional named/component scores and metadata. |

**Fact.** `targets` is a user-facing alias, not a separate execution abstraction: config loading rewrites it to `providers`. For this project the semantic separation “Target under attack” remains useful even though promptfoo implements it with the Provider protocol.

## 2. `redteam init/run/report` flow

`src/main.ts` registers `redteam init`, `eval`, `discover`, `generate`, `run`, `report`, setup, and plugin commands.

`src/redteam/commands/run.ts::redteamRunCommand` describes and invokes a two-step scan. `src/redteam/shared.ts::doRedteamRun` confirms the real flow:

1. load/resolve config and output path;
2. call `doGenerateRedteam` to synthesize/write reusable cases;
3. call the ordinary evaluator (`doEval`) against the Target;
4. persist the Eval and generation duration;
5. open or direct the user to the report.

`src/commands/redteam/report.ts::redteamReportCommand` starts/opens the report UI. Reporting is therefore a view over persisted Eval data, not a separate security adjudicator.

## 3. Plugin, Strategy, and Grader separation

**Fact.** `RedteamPluginBase.generateTests` batches provider-assisted generation, while plugins can override it for datasets or authored inputs. Each case carries plugin metadata and assertions. `applyStrategies` in `src/redteam/index.ts` filters applicable cases and invokes each registered Strategy separately. The Basic strategy controls whether original plugin cases survive; other strategies produce additional/replacement cases.

Strategies present at the fixed commit include:

- deterministic/static transforms: base64, hex, rot13, leetspeak, homoglyph, prompt templates, media encodings;
- generated single-turn variants: composite, GCG, citation, best-of-N;
- iterative single-turn optimization: `jailbreak:meta`, `jailbreak:tree` (each attempt is a separate single turn);
- dynamic multi-turn: crescendo, GOAT, Hydra, Goblin, custom, mischievous-user;
- indirect injection: `indirect-web-pwn`, which hosts/rotates injected web content and can collect a server-side exfiltration receipt;
- regression: `retry`, which loads failed cases from local SQLite or Cloud and replays the actual final attack prompt when available.

`RedteamGraderBase` normally renders a plugin rubric and calls an LLM rubric matcher, but subclasses may override it. Coding-Agent graders first run deterministic verifiers and only fall back to an LLM rubric (`plugins/codingAgent/graders.ts::CodingAgentGrader.getResult`).

## 4. Intent Plugin: string versus nested array

`src/redteam/plugins/intent.ts::IntentPlugin` provides the exact boundary:

- A string intent becomes one ordinary case, with the string injected into the configured variable and an extracted `goal` in metadata.
- A nested string array becomes one case using provider ID `sequence`, with the authored turns in `config.inputs`.
- `src/providers/sequence.ts::SequenceProvider` sends each input in order to the original Target provider and concatenates responses.
- `src/redteam/strategies/util.ts::pluginMatchesStrategyTargets` explicitly excludes provider ID `sequence`; authored multi-step Intents do **not** pass through Strategies.

This answers a key question: a fixed multi-step Intent is a verbatim replay script, not an adaptive attack and not a trajectory generator. Single-string Intents can be mutated by Strategies; nested arrays cannot.

## 5. Multi-step Intent, multi-turn Strategy, and tool trajectory are different objects

| Object | Who chooses the next step? | Uses target feedback? | Is it the Agent's actual tool trace? |
|---|---|---|---|
| Nested-array Intent | Test author, before execution | No | No; it is a sequence of user inputs |
| Multi-turn Strategy | Attack provider during execution | Yes; response, score/rationale, and optionally trace summary | No; it is the adversarial conversation/control loop |
| Agent trajectory | Target Agent/runtime | N/A | Yes, but only if emitted/captured as trace spans or equivalent trusted evidence |

Conflating these would turn “multiple prompts” into a false claim of behavior-trajectory coverage.

## 6. Agent tracing and OpenTelemetry

### Collection and correlation

`src/evaluator.ts` creates W3C trace context and passes `traceparent`, evaluation ID, test-case ID, and indexes through `CallApiContextParams`. `src/tracing/otlpReceiver.ts` accepts bounded OTLP JSON/protobuf traces (and supported OTLP logs), links them to the evaluation, and stores spans. `src/tracing/store.ts` persists/query spans. `src/tracing/traceContext.ts::fetchTraceContext` retrieves a bounded trace with retry and derives tool/guardrail/error insights.

### What promptfoo supplies automatically

Built-in provider calls receive provider-level GenAI spans through promptfoo instrumentation. That establishes model-call timing and correlation, but not necessarily the internal planning/tool loop of an arbitrary remote Agent.

### What the Target must supply

Deep evidence requires the Target/provider to propagate `traceparent` and emit child spans for tools, commands, searches, guardrails, internal model turns, and errors, or to use a provider integration that already exposes them. `src/assertions/trajectoryUtils.ts::extractTrajectorySteps` recognizes generic and framework-specific attributes and normalizes steps into:

- `tool`;
- `command`;
- `search`;
- `reasoning`;
- `message`;
- generic `span`.

**Answer:** promptfoo can execute attacks and collect/normalize the real trajectory supplied by the Target. It does not independently synthesize a truthful Agent tool trajectory.

## 7. Trajectory and Guardrail assertions

`src/assertions/trajectory.ts` implements five trajectory assertions:

| Assertion | Deterministic? | Source behavior |
|---|---|---|
| `trajectory:tool-used` | Yes | Tool name/pattern and optional min/max count |
| `trajectory:tool-args-match` | Yes | Partial or exact structured arguments, with declared defaults/ignored keys |
| `trajectory:tool-sequence` | Yes | Exact sequence or in-order subsequence |
| `trajectory:step-count` | Yes | Count by normalized step type/name/pattern |
| `trajectory:goal-success` | No | LLM judges final output plus compact trajectory summary against a goal |

All have inverse forms through the ordinary `not-` assertion mechanism. Raw-span deterministic assertions also cover span count, duration, and error spans.

Guardrail status is not one of the five trajectory assertions. `src/assertions/guardrails.ts::handleGuardrails` checks `ProviderResponse.guardrails` (or the last red-team-history guardrail result) and distinguishes input/output/general flags. Guardrail spans can still appear in trace ordering, but there is no dedicated deterministic “guardrail-before-tool” assertion at this commit; that composition would need an ordinary custom/JavaScript assertion or a project adapter.

## 8. Trace feedback into attack Strategies

`src/redteam/providers/tracingOptions.ts` defines red-team tracing. It is disabled by default; when enabled, defaults are:

- `includeInAttack: true`;
- `includeInGrading: true`;
- `sanitizeAttributes: true`;
- bounded spans/depth/retries.

Iterative, meta, Hydra, GOAT, and Crescendo provider paths fetch the trace for each attempt/turn. For example, `providers/iterative.ts` passes a compact trace summary into the grader and appends it to attack history for the next mutation; `providers/crescendo/index.ts` includes the prior trace summary in the next attack prompt.

The compact attack summary (`providers/traceFormatting.ts::formatTraceSummary`) contains span names/kinds/durations, tool/model names when present, errors, and derived insights. It intentionally does not include raw tool arguments. The grader path uses `assertions/trajectoryUtils.ts::summarizeTrajectoryForJudge`, which also omits arguments and caps/compacts steps; deterministic assertions retain in-process access to the trace.

**Black-box versus gray-box:** `includeInAttack: false` keeps internal trace out of the attack mutation loop; `true` gives the attacker sanitized internal feedback and is gray-box. Grading may still use trace in either mode, so “attacker black-box” and “evaluator has no internal evidence” are separate properties.

## 9. What graders actually establish

Most red-team graders answer a narrow operational question: did the Target output/action satisfy the plugin's attack objective or violate its rubric? `IntentGrader`, for example, extracts an attacker goal and judges whether the response provided real/actionable completion. `GradingResult.pass` means the configured assertion passed; in red-team metrics, a failed assertion normally represents attack success.

Important limits:

- Purpose is author/config text, not independently verified authorization.
- Plugin IDs and Strategy IDs are test provenance, not ground truth that an attack actually existed or influenced the Agent.
- LLM grader output is an automated judgment and can be wrong or unstable.
- A target refusal short-circuit normally passes many base graders, although specialized graders can override that behavior.
- User `graderExamples`/guidance can override general rubric interpretation.
- Deterministic verifiers can establish specific effects, but only when their fixtures/sidecars/traces are trustworthy and present.

Therefore promptfoo labels cannot be used as human gold labels for attack influence, Agent decision, authorization, objective violation, security-control effect, or real-world impact without independent adjudication.

## 10. Indirect injection and effect receipts

There are two relevant mechanisms:

- `plugins/indirectPromptInjection.ts` generates/judges indirect-instruction susceptibility.
- `strategies/indirectWebPwn.ts` creates instrumented web pages, rotates injection placement, and queries a server-side exfiltration tracking receipt. `assertions/redteam.ts::handleRedteam` adds that receipt to grading context.

The latter is especially useful to this project: it shows that a grader can combine an attack with a deterministic external effect receipt. It is still a specialized hosted flow, not a general Evidence Resolver or arbitrary network oracle.

## 11. Reporting, persistence, cache, CI, and regression

- `src/models/eval.ts::Eval` and `evalResult.ts::EvalResult` persist configuration, results, trace linkage, metadata, target identity, tags, timing, and red-team status to the local database.
- Red-team reports group findings and calculate attack-success/risk metrics over assertion results.
- Provider/fetch caching is built in and can be disabled with `--no-cache`; cache identity includes request material, and secret-bearing identity is hashed/HMACed rather than written raw in keys.
- CLI output supports JSON, HTML, CSV and JUnit-compatible paths through the general evaluator/export layer.
- Eval tags can carry target build/CI run/Git SHA metadata.
- Standard Eval thresholds and exit codes can be used as CI gates.
- `retry` retrieves previous failed cases and replays them, while ordinary targeted tests/trajectory assertions can preserve a discovered vulnerability as a narrow regression.

**Project use: ADOPT/ADAPT.** Reuse this lifecycle, but a security-vulnerability artifact needs stronger environment/fixture/oracle versioning than a generic Eval row alone.

## 12. Sensitive-data risks

The source implements several controls but does not make trace ingestion secret-proof:

- provider request/response bodies are truncated and sanitized by default;
- trace queries sanitize credential-like attribute **keys** by default;
- OTLP receiver policies can redact configured attributes;
- attack/grader summaries omit raw tool arguments;
- deterministic assertions can inspect richer trace data in process.

Residual risks:

- secrets in span names, tool names, status messages, unrecognized attribute keys, raw provider output, generated test variables, or custom grader prompts may still persist or reach an LLM;
- `sanitizeAttributes: false` exposes raw values;
- `includeInAttack: true` shares structural internals with the attack provider;
- traces and histories are persisted and displayed.

The project must therefore enforce a stricter secret boundary: trusted deterministic verification may compare a secret by hash/receipt, but raw secret values must not enter attacker feedback or any LLM-facing representation.

## 13. Documentation/source consistency

| Severity | Finding | Evidence | Disposition |
|---|---|---|---|
| — | Intent documentation says nested arrays execute verbatim and skip Strategies | `plugins/intent.ts`, `providers/sequence.ts`, `strategies/util.ts` | Consistent |
| — | Agent docs say deeper trajectory evidence needs Target instrumentation | evaluator trace propagation and OTLP/trajectory source | Consistent |
| — | Docs say trajectory can feed grading and compatible adaptive Strategies | iterative/meta/Hydra/GOAT/Crescendo source paths | Consistent |
| P2 | “Black-box” wording can be misread as no internal evaluator evidence | `includeInAttack: false` hides trace only from the attacker; `includeInGrading` can remain true | Terminology needs explicit attacker-view/evaluator-view fields in our project |
| P2 | High-level marketing can imply that tracing observes Agent internals automatically | Built-in spans guarantee provider-call instrumentation; arbitrary Agent tools still require child spans/integration | Keep the deeper-instrumentation caveat next to any adoption claim |

No material README/source contradiction was found for the scoped Intent, trace, Strategy, or trajectory-assertion behavior at the fixed commit.

## 14. Direct answers for this project

1. **Can promptfoo generate a real Agent trajectory?** No. It generates/executes attacks and collects the Target's instrumented real behavior.
2. **How do multi-step Intent, multi-turn Strategy, and tool trace relate?** Authored input script, adaptive attacker loop, and observed Agent behavior respectively; they must remain distinct artifacts.
3. **Which labels are not human gold?** Plugin/Strategy IDs, extracted goals, assertion pass/fail, rubric scores, and attack-success metrics unless independently adjudicated.
4. **Best role in our product?** Principal outer loop for attack generation/mutation, Target execution, trace collection, assertion execution, reports, cache, CI, replay, and regression.
5. **Which features require Target instrumentation?** Internal tools/arguments/order, guardrail ordering, planner/model rounds, commands/searches, and deep errors. Provider-level calls alone are insufficient.

## 15. Project disposition

- **ADOPT:** Plugin/Strategy/Target/Assertion separation, redteam run lifecycle, reports/tags/cache/CI, fixed-sequence and adaptive-attack distinction, retry/regression pattern.
- **ADAPT:** Provider/Target contract, OpenTelemetry normalization, deterministic trajectory assertions, effect receipts, and vulnerability persistence.
- **EXPERIMENT:** trace-informed attack mutation and LLM trajectory-goal grading.
- **REJECT:** promptfoo-generated labels or LLM grader results as complete human security ground truth.
