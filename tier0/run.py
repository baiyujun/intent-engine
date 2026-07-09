"""CLI entry point for Tier 0 dual-path judge.

Usage::

    python -m tier0.run --input "some text to evaluate"
    python -m tier0.run --input batch.jsonl --output json
    python -m tier0.run --input "text" --build-index  # rebuild FAISS index first
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .fusion import judge, Tier0Verdict, build_index
from .text_preprocess import normalize_text

# in-repo dataset path (merged from the former standalone dataset repo)
_REPO = Path(__file__).resolve().parents[1]
_DEFAULT_TRAIN = _REPO / "dataset" / "processed" / "train.jsonl"


def _format_json(verdict: Tier0Verdict) -> dict:
    """Convert Tier0Verdict to a JSON-serialisable dict."""
    return {
        "rule_risk": verdict.rule_risk,
        "rule_d1": verdict.rule_d1,
        "rule_d2": verdict.rule_d2,
        "rule_d3": verdict.rule_d3,
        "rule_matched_patterns": verdict.rule_matched_patterns,
        "rule_short_circuit": verdict.rule_short_circuit,
        "vector_margin": round(verdict.vector_margin, 6),
        "vector_d_benign": round(verdict.vector_d_benign, 6),
        "vector_d_malicious": round(verdict.vector_d_malicious, 6),
        "escalated": verdict.escalated,
        "escalation_reasons": verdict.escalation_reasons,
        "final_verdict": verdict.final_verdict,
        "path_a_ms": round(verdict.path_a_ms, 2),
        "path_b_ms": round(verdict.path_b_ms, 2),
        "total_ms": round(verdict.total_ms, 2),
    }


def _format_table(verdict: Tier0Verdict) -> str:
    """Human-readable table format."""
    lines = [
        "=== Tier 0 Verdict ===",
        f"  Rule risk      : {verdict.rule_risk}",
        f"  Rule D1/D2/D3  : {verdict.rule_d1}/{verdict.rule_d2}/{verdict.rule_d3}",
        f"  Short-circuit  : {verdict.rule_short_circuit or '(none)'}",
        f"  Patterns matched: {len(verdict.rule_matched_patterns)}",
        f"  Vector margin  : {verdict.vector_margin:+.4f} (d_ben={verdict.vector_d_benign:.2f} d_mal={verdict.vector_d_malicious:.2f})",
        f"  Escalated      : {verdict.escalated}",
        f"  Final verdict  : {verdict.final_verdict}",
        f"  Timing         : path_a={verdict.path_a_ms:.1f}ms path_b={verdict.path_b_ms:.1f}ms total={verdict.total_ms:.1f}ms",
    ]
    if verdict.escalation_reasons:
        lines.append("  Escalation reasons:")
        for r in verdict.escalation_reasons:
            lines.append(f"    - {r}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="tier0",
        description="Tier 0 dual-path intent judge (rule engine + vector retrieval)",
    )
    parser.add_argument(
        "--input", required=True,
        help="Input text to evaluate, or path to a .jsonl file for batch mode",
    )
    parser.add_argument(
        "--output", choices=["json", "table"], default="table",
        help="Output format (default: human-readable table)",
    )
    parser.add_argument(
        "--models-dir", default="tier0/models",
        help="Directory for FAISS index files (default: tier0/models)",
    )
    parser.add_argument(
        "--build-index", action="store_true",
        help="Rebuild the FAISS index from dataset train.jsonl before querying",
    )
    parser.add_argument(
        "--train-path", default=str(_DEFAULT_TRAIN),
        help="Path to train.jsonl for index building (default: dataset train split)",
    )
    args = parser.parse_args(argv)

    # --build-index: rebuild before querying
    if args.build_index:
        from .vector_index import build_index as vi_build
        print(f"Building index from {args.train_path} → {args.models_dir}", file=sys.stderr)
        result = vi_build(args.train_path, save_dir=args.models_dir)
        print(f"Index built: {result['benign_count']} benign, {result['malicious_count']} malicious", file=sys.stderr)

    # Determine if single text or batch
    input_path = Path(args.input)
    if input_path.exists() and input_path.suffix == ".jsonl":
        # Batch mode
        from .vector_index import _read_jsonl
        records = _read_jsonl(str(input_path))
        results = []
        for rec in records:
            # Extract text from record
            text_parts = [t.get("raw_text", "") for t in rec.get("turns", [])]
            text = " ".join(text_parts) if text_parts else str(rec)
            v = judge(text, models_dir=args.models_dir)
            results.append(_format_json(v))
        if args.output == "json":
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            for i, r in enumerate(results):
                print(f"--- Record {i+1} ---")
                for k, val in r.items():
                    print(f"  {k}: {val}")
    else:
        # Single text mode
        v = judge(args.input, models_dir=args.models_dir)
        if args.output == "json":
            print(json.dumps(_format_json(v), indent=2, ensure_ascii=False))
        else:
            print(_format_table(v))


if __name__ == "__main__":
    main()
