"""Shared dataset loading for Tier1 evaluation harnesses."""

import json
from pathlib import Path


def _load_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def load_multiturn_holdout(data_root):
    """Load the reviewed mixed-label holdout plus legacy benign controls."""
    processed = Path(data_root) / "processed"
    reviewed = _load_jsonl(processed / "test_holdout_multiturn.jsonl")
    legacy_path = processed / "test_holdout_multiturn_benign.jsonl"
    legacy_benign = _load_jsonl(legacy_path) if legacy_path.exists() else []
    records = reviewed + legacy_benign
    malicious = [record for record in records if record["label"]["is_malicious"]]
    benign = [record for record in records if not record["label"]["is_malicious"]]
    return {
        "reviewed": reviewed,
        "legacy_benign": legacy_benign,
        "records": records,
        "malicious": malicious,
        "benign": benign,
        "counts": {
            "reviewed": len(reviewed),
            "legacy_benign": len(legacy_benign),
            "malicious": len(malicious),
            "benign": len(benign),
            "total": len(records),
        },
    }
