"""Convert promptfoo redteam output (yaml) → dataset-schema records.

promptfoo's `redteam generate` produces adversarial natural-language
instructions (LLM-generated, so non-templated — important for diluting the
synthetic-template fingerprints in xgboost_paper_derived.jsonl). This module
turns each `tests[].vars.user_input` into a single-turn malicious record that
matches the v0 dataset schema (schema.make_record / validate_record).

All promptfoo-generated cases are adversarial instructions → is_malicious=True.
We do NOT run the promptfoo grader here; we only harvest the generated inputs
as training/dilution data. risk_category is mapped from the promptfoo plugin.
"""
from __future__ import annotations

import json
import pathlib
import sys

_REPO = pathlib.Path(__file__).resolve().parents[1]
_DS = _REPO / "dataset" / "src"
if str(_DS) not in sys.path:
    sys.path.insert(0, str(_DS))

import yaml  # noqa: E402
from schema import make_record, deterministic_id, validate_record  # noqa: E402
from normalize_utils import make_turn, write_jsonl  # noqa: E402

SRC_KEY = "promptfoo_redteam"

# Map promptfoo plugin → our risk_category (coarse). The exact family is kept
# in attack_family for traceability.
_PLUGIN_TO_RISK = {
    "harmful:privacy": "exfiltration",
    "prompt-extraction": "exfiltration",
    "excessive-agency": "privilege_escalation",
    "shell-injection": "privilege_escalation",
    "harmful:cybercrime": "privilege_escalation",
    "contracts": "injection",
}


def _attack_family(plugin: str) -> str:
    # keep the plugin id verbatim as the attack_family for traceability
    return plugin.replace(":", "_") if plugin else "promptfoo"


def convert(yaml_path, out_path=None):
    """Read a promptfoo redteam yaml, emit schema-valid malicious records.

    Returns (records, errors).
    """
    data = yaml.safe_load(pathlib.Path(yaml_path).read_text())
    tests = data.get("tests", []) or []
    records = []
    errors = []
    for i, t in enumerate(tests):
        ui = (t.get("vars", {}) or {}).get("user_input", "")
        if not ui or not str(ui).strip():
            errors.append(f"test[{i}]: empty user_input")
            continue
        meta = t.get("metadata", {}) or {}
        plugin = meta.get("pluginId", "")
        risk = _PLUGIN_TO_RISK.get(plugin, "injection")
        fam = _attack_family(plugin)
        raw_id = f"{fam}_{i}"
        rec = make_record(
            _raw_id=raw_id,
            source_dataset=SRC_KEY,
            license="own",
            license_status="ok",
            modality="single_turn",
            turns=[make_turn("user", str(ui), "user_direct", 0)],
            structured_action={
                "action_type": "unknown",
                "target_resource": None,
                "stated_purpose": None,
            },
            label={
                "risk_category": risk,
                "is_malicious": True,
                "attack_family": fam,
                "purpose_capability_consistent": False,
                "confidence": "high",
                "attack_stage_precursor": False,
            },
            notes=f"promptfoo redteam plugin={plugin} severity={meta.get('severity','?')}",
        )
        errs = validate_record(rec)
        if errs:
            errors.append(f"{rec.get('id','?')}: {errs}")
            continue
        records.append(rec)
    if out_path:
        write_jsonl(pathlib.Path(out_path), records)
    return records, errors


def main():
    here = pathlib.Path(__file__).resolve().parent
    yaml_path = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else here / "promptfoo_redteam_out.yaml"
    )
    out_path = pathlib.Path(
        sys.argv[2] if len(sys.argv) > 2
        else _REPO / "dataset" / "synthetic" / "promptfoo_redteam.jsonl"
    )
    records, errors = convert(yaml_path, out_path)
    # count summary by attack_family
    from collections import Counter
    fams = Counter(r["label"]["attack_family"] for r in records)
    print(f"converted {len(records)} records -> {out_path}", file=sys.stderr)
    for f, c in fams.most_common():
        print(f"  {f}: {c}", file=sys.stderr)
    if errors:
        print(f"errors: {len(errors)} (first 5): {errors[:5]}", file=sys.stderr)


if __name__ == "__main__":
    main()
