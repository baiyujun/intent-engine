# Vigil-LLM Pluggable Detector Pattern (local clone FAILED)

**Status**: git clone to /home/hjy/refs/vigil-llm failed after 7+ attempts (GitHub HTTPS connection reset from this WSL2 environment). WebFetch to github.com and raw.githubusercontent.com also timed out (60s). This note is therefore a **best-effort reconstruction** from the project README (cached in search snippets) and general knowledge of the scanner architecture. Gaps are clearly marked.

## Project Overview
Vigil-LLM (by deadbits) is a prompt-injection and jailbreak detection toolkit for LLM inputs. It runs multiple independent scanners over the input text and combines their outputs into a risk verdict.

## Detector / Scanner Architecture (RECONSTRUCTED — verify against source when network allows)

Based on the README description and common patterns in similar toolkits:

### Scanner Types
1. **YARA Scanner**: Matches input against YARA rules (regex-like patterns for known injection signatures)
2. **Transformer Classifier**: Runs a fine-tuned classifier model (likely a small BERT/distilbert) to predict injection probability
3. **Vector Similarity Scanner** (ChromaDB): Embeds the input and compares against known-bad and known-good embeddings stored in a ChromaDB vector store; returns similarity scores

### Base Interface (inferred)
Each scanner likely implements a common interface, something like:
```
class Scanner(ABC):
    @abstractmethod
    def analyze(self, prompt: str) -> ScanResult:
        """Return structured result with score, label, details."""
```
- `ScanResult` probably contains: `score` (float 0-1), `label` (str: benign/suspicious/malicious), `details` (dict with rule names or matched patterns)

### Composition Pattern
- A `Vigil` or `Pipeline` class holds a list of scanners
- For each input, all scanners run independently
- Results are aggregated: likely a weighted sum, max-score, or voting ensemble
- Short-circuit: if any scanner returns a very high score (e.g. >0.95), the pipeline may skip remaining scanners and return early

### Key Design Elements to Adopt
1. **Independent, pluggable scanners**: Each scanner is self-contained, can be added/removed without affecting others
2. **Common result format**: All scanners return the same type (score + label + details)
3. **Pipeline composition**: A simple loop/fan-out that runs all scanners and merges
4. **Short-circuit on high confidence**: Early exit when one detector is very confident

## Gaps / Unknowns
- Exact base class method names and signatures (could be `scan()` instead of `analyze()`)
- How ChromaDB store is populated and queried
- Weight scheme for result merging
- Whether scanners are run concurrently or sequentially
- Any registry/factory pattern for scanner discovery

## Pattern to Adopt for Tier 0

Map vigil's detector interface onto our tier0 dual-path judge:

| Vigil-LLM concept | Our Tier 0 equivalent |
|---|---|
| Scanner base class | `Judge` ABC with `judge(text, context) -> Verdict` |
| YARA scanner | Path A: RuleEngine (attack_patterns.yaml + D1-D3 scoring) |
| Transformer scanner | Not in v0 (would be Tier 2 LLM arbiter) |
| Vector/ChromaDB scanner | Path B: VectorRetriever (MiniLM embedding + FAISS NN index) |
| Pipeline composition | `Tier0Judge` class that fans out to Path A + Path B |
| Result merging | Fusion: compare rule_verdict and margin sign; agree → trust, disagree → escalate |
| Short-circuit | If RuleEngine returns CRITICAL/HIGH with SC match → skip Path B, return immediately |

**TODO**: Re-read actual vigil-llm source when GitHub access is restored, and update this note with exact interface details.
