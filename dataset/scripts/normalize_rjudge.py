"""Normalize R-Judge -> unified records. license_status=needs_confirmation (no LICENSE).

Real data layout: ``raw/rjudge/data/<scenario>/<name>.json`` are JSON ARRAYS of
records with keys ``id, scenario, profile, goal, contents, label,
risk_description, attack_type``. ``contents`` is a NESTED list: a list of
turn-groups, where each turn-group is itself a list of turn-dicts
``{role, content, thought}`` (plus sometimes ``action`` for agent turns).

The previous implementation iterated every ``*.json`` under ``raw/rjudge`` —
including ``config/data_schema.json``, which is a DICT (not a list) — and then
called ``.get`` on its string keys, raising
``AttributeError: 'str' object has no attribute 'get'`` and producing 0 records.
This rewrite only processes ``data/*/*.json``, skips any non-list JSON file
(silently), skips records without a ``label`` key, and flattens the nested
``contents`` into sequential turns.
"""
import json, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx

SRC_KEY = "rjudge"
RAW_DIR = pathlib.Path("raw/rjudge")
DATA_DIR = RAW_DIR / "data"


def _flatten_turns(contents, fallback_text: str):
    """Flatten the nested ``contents`` structure into sequential ``make_turn``s.

    ``contents`` is a list of turn-groups; each turn-group is a list of
    turn-dicts. Returns ``[make_turn(...), ...]``. If ``contents`` is empty
    or yields no turns, fall back to a single ``user`` turn from ``fallback_text``
    (the record's ``goal``).
    """
    turns = []
    idx = 0
    if isinstance(contents, list):
        for group in contents:
            if not isinstance(group, list):
                # Be defensive: a stray dict directly under contents — treat as
                # a single-turn group so we don't silently drop records.
                group = [group] if isinstance(group, dict) else []
            for turn in group:
                if not isinstance(turn, dict):
                    continue
                role = "user" if turn.get("role") == "user" else "agent_plan"
                raw_text = turn.get("content", "")
                if raw_text is None:
                    raw_text = ""
                turns.append(make_turn(role, raw_text, "user_direct", idx))
                idx += 1
    if not turns:
        turns = [make_turn("user", fallback_text or "", "user_direct", 0)]
    return turns


def main():
    base = DATA_DIR if DATA_DIR.exists() else pathlib.Path("tests/fixtures/rjudge")
    recs = []
    # Only process data/*/*.json — never touch config/ (data_schema.json is a
    # dict, not a list, and iterating it was the crash source).
    for f in sorted(base.rglob("*.json")):
        try:
            data = json.loads(f.read_text())
        except Exception:
            continue
        if not isinstance(data, list):
            # Skip non-array files (e.g. config/data_schema.json which is a dict).
            continue
        file_stem = f.stem
        for record in data:
            if not isinstance(record, dict):
                continue
            if "label" not in record:
                # No label -> cannot classify; skip rather than crash.
                continue
            try:
                label_val = int(record.get("label"))
            except (TypeError, ValueError):
                continue
            unsafe = (label_val == 1)
            is_malicious = unsafe
            modality = "multi_turn"
            turns = _flatten_turns(record.get("contents", []), record.get("goal", ""))
            attack_family = record.get("attack_type") or ("goal_hijack" if unsafe else "benign")
            risk_category = "unauthorized_action" if unsafe else "benign"
            purpose_capability_consistent = not unsafe
            notes = record.get("risk_description", "")
            raw_id = record.get("id")
            if raw_id is not None and str(raw_id) != "":
                raw_id = f"{file_stem}_{raw_id}"
            else:
                raw_id = file_stem
            recs.append(make_record(
                _raw_id=raw_id, source_dataset=SRC_KEY,
                license=license_spdx(SRC_KEY), license_status=license_status(SRC_KEY),
                modality=modality, turns=turns,
                structured_action={"action_type": "unknown",
                                   "target_resource": record.get("scenario"),
                                   "stated_purpose": record.get("goal")},
                label={"risk_category": risk_category,
                       "is_malicious": is_malicious,
                       "attack_family": attack_family,
                       "purpose_capability_consistent": purpose_capability_consistent,
                       "confidence": "high",
                       "attack_stage_precursor": False},
                notes=notes,
            ))
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice(SRC_KEY, recs)


if __name__ == "__main__":
    main()
