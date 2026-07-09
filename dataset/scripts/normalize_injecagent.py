"""Normalize InjecAgent test_cases_*.json arrays -> unified records.

Real data: ``raw/injecagent/data/test_cases_{ds,dh}_{base,enhanced}.json`` are
JSON arrays of objects. Each object describes an indirect prompt-injection
scenario: a benign ``User Instruction`` + ``User Tool`` plus a
``Tool Response Template`` that embeds a literal ``<Attacker Instruction>``
placeholder (the injected payload carried inside tool output). We emit one
unified record per object: turn 0 = the benign user goal (``user_direct``),
turn 1 = the tool response template (``tool_output`` — the indirect injection).
"""
import json
import pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx

SRC_KEY = "injecagent"
RAW_DIR = pathlib.Path("raw/injecagent")


def _iter_test_case_files(d: pathlib.Path):
    """Yield test_cases_*.json arrays under the data dir (real or fixture)."""
    return sorted(p for p in d.rglob("test_cases_*.json") if p.is_file())


def main():
    d = RAW_DIR if RAW_DIR.exists() else pathlib.Path("tests/fixtures/injecagent")
    recs = []
    for f in _iter_test_case_files(d):
        stem = f.stem
        try:
            with f.open() as fh:
                arr = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(arr, list):
            continue
        for idx, obj in enumerate(arr):
            if not isinstance(obj, dict):
                continue
            user_instruction = (obj.get("User Instruction") or "").strip()
            tool_template = obj.get("Tool Response Template") or ""
            if not user_instruction or not tool_template:
                continue
            user_tool = obj.get("User Tool") or ""
            attack_type = obj.get("Attack Type") or ""
            rec = make_record(
                _raw_id=f"{stem}#{idx}",
                source_dataset=SRC_KEY,
                license=license_spdx(SRC_KEY),
                license_status=license_status(SRC_KEY),
                modality="single_turn",
                turns=[
                    make_turn("user", user_instruction, "user_direct", 0),
                    make_turn("tool_output", tool_template, "tool_output", 1),
                ],
                structured_action={
                    "action_type": "unknown",
                    "target_resource": user_tool,
                    "stated_purpose": user_instruction,
                },
                label={
                    "risk_category": "prompt_injection",
                    "is_malicious": True,
                    "attack_family": "indirect_injection",
                    "purpose_capability_consistent": False,
                    "confidence": "high",
                    "attack_stage_precursor": False,
                },
                notes=f"injecagent attack_type={attack_type}",
            )
            recs.append(rec)
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)


if __name__ == "__main__":
    main()
