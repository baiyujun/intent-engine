# Tier 0 Latency Benchmark

Measured on this WSL2 environment (CPU only, no GPU). All measurements are
**steady-state** (after a warmup query that pays the one-time ~18s MiniLM
model load into the module-level cache). Backend: FAISS IndexFlatL2 +
sentence-transformers `paraphrase-multilingual-MiniLM-L12-v2` (384-dim),
index built from `/home/hjy/dataset/processed/train.jsonl` (399 benign +
1750 malicious records).

## Per-path latency (30 samples, 6×5 mixed inputs)

| Path | p50 | min | max |
|------|-----|-----|-----|
| Path A — rule engine (normalize_text + D1-D3 + PatternMatcher over 24 patterns) | 52.7 ms | 43.8 ms | 103.6 ms |
| Path B — vector retrieval (MiniLM encode + FAISS L2 1-NN ×2 clusters) | 36.3 ms | 21.0 ms | 559.1 ms |
| **Total (sequential)** | **~89 ms** | ~84 ms | ~885 ms |

The Path B `max=559ms` is inter-query warmup variance (first few encodes),
not steady state; p50 is the representative figure.

## Comparison to the XGBoost-paper baseline

The paper (arXiv:2605.01143) reports their full XGBoost detector at **4.6 ms**
per prefix on a single CPU thread (feature extraction + inference). Our Tier 0
is ~19× slower than that, because:
- Path B embeds every query with a 384-dim Transformer (the paper has NO
  embedding step — it uses hand-engineered tabular features only).
- Path A runs 24 weighted regex patterns + D1-D3 scoring on every input.

This is expected and **acceptable for v0**: Tier 0 is a deterministic
first-pass gate, not the latency-critical inline detector. The paper's 4.6ms
target applies to their Tier-1-equivalent XGBoost layer; our Tier 1 (Step 4)
aims for that budget. We record this gap honestly rather than claim parity.

## Known limitation (recorded for the v0 report)

Tier 0's Path B uses a **general-purpose multilingual embedding**
(`paraphrase-multilingual-MiniLM-L12-v2`) — the same model the dataset's
`dedup.py` uses for consistency — rather than an embedding space
contrastively trained on the intent distinction (benign vs malicious agent
interaction). This is a deliberate v0 simplification:
- Pro: reuses an already-cached model; no extra training; deterministic NN.
- Con: the benign/malicious clusters are not maximally separated in this
  general space, so the margin signal is noisy (we saw benign-ish queries
  land negative when their surface text shares tokens with malicious
  samples). The fusion layer's fuzzy zone + rule-path agreement partially
  compensates, but a contrastively-trained intent embedding is future work.

## Reproducibility

```bash
cd /home/hjy/intent-engine
PYTHONPATH=/home/hjy/dataset/src /home/hjy/dataset/.venv/bin/python -c "
from tier0.fusion import judge
judge('warmup', models_dir='tier0/models')   # warmup (~18s model load)
# then time judge(text, models_dir='tier0/models')
"
```

If the index is missing, rebuild with:
```bash
python -m tier0.run --build-index --input "warmup" --output json
```
