# intent-engine

v0 prototype of a layered intent-recognition guardrail for AI agents.

## Layers
- **Tier 0** — local deterministic dual-path judge (rule engine + vector retrieval).
- **Tier 1** — session-level structured features + XGBoost.
- **Tier 2** — LLM semantic arbiter (stub in v0).
- **Tier 3** — deep review (stub in v0).

## Layout
- `notes/`   — reference-implementation study notes (Step 1)
- `tier0/`   — dual-path judge
- `synth/`   — XGBoost-paper-derived synthetic data generator (writes into the `dataset` repo)
- `tier1/`   — feature engineering + XGBoost
- `tier2/`,`tier3/` — stubs
- `reports/` — evaluation reports

## Environment
Shares the `dataset` repo venv at `/home/hjy/dataset/.venv` (adds
`faiss-cpu`, `xgboost`, `sentence-transformers`). See `requirements.txt`.

This is a defensive-security research prototype. No live attacks are performed.
