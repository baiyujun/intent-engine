> [!IMPORTANT]
> **Archived legacy project**
>
> This repository contains the historical implementation of the
> `intent-engine` layered intent-recognition and online guardrail prototype.
>
> It is preserved for research history, experiment reproducibility, and audit
> purposes. It is no longer under active development and is not the codebase
> for the current Agent security evaluation and fuzzing system.
>
> Active development continues in:
> <https://github.com/baiyujun/agent-security-eval>
>
> The new project uses a clean repository because its domain model, execution
> architecture, evidence model, and evaluation goals are fundamentally
> different from this legacy prototype.

# intent-engine

v0 prototype of a layered intent-recognition guardrail for AI agents.

## Layers
- **Tier 0** — local deterministic dual-path judge (rule engine + vector retrieval).
- **Tier 1** — session-level structured features + XGBoost.
- **Tier 2** — LLM semantic arbiter (stub in v0).
- **Tier 3** — deep review (stub in v0).

## Layout
- `notes/`    — reference-implementation study notes (Step 1)
- `tier0/`    — dual-path judge
- `synth/`    — XGBoost-paper-derived synthetic data generator (writes into `dataset/`)
- `tier1/`    — feature engineering + XGBoost
- `tier2/`, `tier3/` — stubs
- `dataset/`  — the unified agent-intent dataset (merged in from its former
  standalone repo; see `dataset/README.md`). Holds `processed/` (train/val/test
  splits), `synthetic/`, `scripts/`, `src/` (the `schema` / `normalize_utils` /
  `licenses` modules the guardrail imports), and `reports/`.
- `reports/`  — evaluation reports

## Environment
A Python venv with `faiss-cpu`, `xgboost`, `sentence-transformers`,
`scikit-learn`, `pyyaml`. The repo historically shares a venv under
`dataset/.venv`; on a fresh clone create one and `pip install -r requirements.txt`.
Import: `conftest.py` inserts `dataset/src` + the repo root onto `sys.path`, so a
bare `pytest` resolves the flat `from schema import …` imports.

This is a defensive-security research prototype. No live attacks are performed.
