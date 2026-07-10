# Part 1 — Multi-Turn Holdout Test Set via promptfoo GOAT/Crescendo

## Method (100% promptfoo — no hand-written generation)

The key discovery: `promptfoo redteam generate` with `crescendo`/`goat` strategies produces **single-turn** test cases. The multi-turn conversation is built during `redteam eval` — GOAT/Crescendo are **providers** that run a live multi-turn conversation against a target, not offline generators. So the correct flow is:

1. `redteam generate` → wraps test cases with `promptfoo:redteam:goat` provider
2. `redteam eval` → GOAT runs up to `maxTurns=5` live conversation turns against the DeepSeek target, building a `messages[]` array (user/assistant alternating)
3. Harvest `metadata.messages` from the eval output → convert to our schema

This is the promptfoo real multi-turn engine. Only glue code was written (`synth/multiturn_convert.py` extracts user turns from `messages` and writes schema records).

## Configs

- `synth/promptfoo_multiturn.yaml` — main: 20 coding-agent/agentic plugins × 5, strategies goat + crescendo (270 cases)
- `synth/promptfoo_multiturn_supplement.yaml` — supplement: 10 plugins × 5, goat only (100 cases, run at concurrency 6)
- Target: `deepseek:deepseek-v4-flash` (native DeepSeek provider — note: v0.1's `openai:chat:deepseek-v4-flash` + `apiKeyName` was a latent bug, only `generate` worked because it never called the target; `apiKeyEnvar` / `deepseek:*` is the correct form)

## Data Generated

**Malicious multi-turn holdout** (`dataset/processed/test_holdout_multiturn.jsonl`):
- 51 records, 14 attack families
- Turn distribution: {2: 14, 3: 5, 4: 3, 5: 28, 10: 1}
- Sources: GOAT (44) + Crescendo (7) live multi-turn conversations
- All structurally novel — escalating pretext across turns (IT-audit / debugging / deployment impersonation), NO overlap with the 4 templated families in training

**Benign multi-turn controls** (`dataset/processed/test_holdout_multiturn_benign.jsonl`):
- 40 records, 8 task archetypes (code review, debugging, docs, deployment, refactoring, testing, feature dev, perf tuning)
- Turn distribution: {3: 16, 4: 16, 5: 8}

## Honest Caveat — promptfoo Benign Path

promptfoo's redteam module is **adversarial-only**; `generate dataset` (the benign generator) **crashes** at persona synthesis (`TypeError: Cannot read properties of undefined (reading 'length')`). So for the benign multi-turn controls, the LLM (DeepSeek, same engine) was called directly via the OpenAI-compatible API with only **splitting glue code** (parse `USER:`-prefixed lines into turns). The generation logic itself is the LLM's; we did not hand-write attack/task content. This is a reported tooling gap, not a silent fallback.

## Honest Caveat — Rate / Speed

The full 270-case GOAT eval was slow (GOAT runs 5-turn conversations, API-bound; a `--resume` added only ~1 result per 7 min). To get a robust holdout without over-running, we ran a focused 100-case GOAT supplement at concurrency 6 (8m50s) and combined. Final n=51 malicious is smaller than the single-turn holdout (793) but sufficient for a meaningful prefix-level AUC (357 prefixes).
