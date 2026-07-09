# Agent Intent-Recognition Dataset (v0)

Reproducible pipeline for an Agent intent-recognition training/eval dataset.

## Reproduce
1. `python3 -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt` (core). Optionally `pip install -r requirements-extras.txt` for embedding-based dedup (pulls torch ~1GB); without it dedup/split use TF-IDF.
3. `make pipeline`  (or `python3 scripts/run_pipeline.py --all`)
4. Outputs: `processed/{train,val,test_indist,test_holdout_family}.jsonl`, `reports/data_card.md`, `reports/coverage_gaps.md`

## Run a single source / resume
- `python3 scripts/run_pipeline.py --sources agentdojo,injecagent`
- Failed sources are logged to `reports/fetch_errors.log` and skipped; re-run resumes.

## License gate
See `scripts/license_config.yaml`. Only `license_status: ok` sources enter train/val/test.
Conservative default: unknown/custom/no-license sources are held in `unified.jsonl` only.

## Incremental refresh
`reports/fetch_manifest.json` records `fetched_at` + `source_ref` per source. Re-running
`fetch_<source>.py` pulls new commits; `normalize_<source>.py` overwrites the per-source slice.
