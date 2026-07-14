"""Convert promptfoo GOAT/Crescendo multi-turn eval output → dataset-schema records.

Extracts the conversation `messages` from each GOAT/Crescendo test result,
keeps only the user (attacker) turns as our multi-turn record's turns,
and stores the full conversation metadata in notes for traceability.

This module is the GLUE between promptfoo's real multi-turn generation engine
and our v0 dataset schema. It does NOT generate any content itself — promptfoo
does that via GOAT/Crescendo live evaluation.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

_REPO = pathlib.Path(__file__).resolve().parents[1]
_DS = _REPO / "dataset" / "src"
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
if str(_DS) not in sys.path:
    sys.path.insert(0, str(_DS))

import yaml  # noqa: E402
from schema import make_record, deterministic_id, validate_record  # noqa: E402
from normalize_utils import make_turn, write_jsonl  # noqa: E402
from synth.multiturn_relabel import (  # noqa: E402
    apply_adjudications,
    build_adjudications,
    match_source_evidence,
)

SRC_KEY = "promptfoo_multiturn"

# Map promptfoo strategy → our risk_category
_STRATEGY_TO_RISK = {
    "goat": "privilege_escalation",
    "crescendo": "exfiltration",
}

# Map promptfoo plugin → risk_category (same mapping as v0.1 promptfoo_convert)
_PLUGIN_TO_RISK = {
    "coding-agent:automation-poisoning": "injection",
    "coding-agent:delayed-ci-exfil": "exfiltration",
    "coding-agent:generated-vulnerability": "privilege_escalation",
    "coding-agent:network-egress-bypass": "exfiltration",
    "coding-agent:procfs-credential-read": "exfiltration",
    "coding-agent:repo-prompt-injection": "injection",
    "coding-agent:sandbox-read-escape": "exfiltration",
    "coding-agent:sandbox-write-escape": "privilege_escalation",
    "coding-agent:secret-env-read": "exfiltration",
    "coding-agent:secret-file-read": "exfiltration",
    "coding-agent:steganographic-exfil": "exfiltration",
    "coding-agent:terminal-output-injection": "injection",
    "coding-agent:verifier-sabotage": "injection",
    "excessive-agency": "privilege_escalation",
    "indirect-prompt-injection": "injection",
    "shell-injection": "privilege_escalation",
    "data-exfil": "exfiltration",
    "rag-document-exfiltration": "exfiltration",
    "tool-discovery": "privilege_escalation",
}


def _risk_category(metadata: dict) -> str:
    strategy = metadata.get("strategyId", "")
    plugin = metadata.get("pluginId", "")
    return _STRATEGY_TO_RISK.get(strategy) or _PLUGIN_TO_RISK.get(plugin) or "injection"


def _attack_family(metadata: dict) -> str:
    strategy = metadata.get("strategyId", "")
    plugin = metadata.get("pluginId", "")
    parts = []
    if strategy:
        parts.append(strategy)
    if plugin:
        parts.append(plugin.replace(":", "_"))
    return "_".join(parts) if parts else "multiturn"


def convert(
    eval_json_path,
    out_path=None,
    min_user_turns=2,
    adjudications=None,
    record_index_offset=0,
):
    """Read promptfoo multi-turn output and apply reviewed, schema-valid labels.

    Only keeps conversations with >= min_user_turns user (attacker) turns
    to ensure genuine multi-turn attack chains.

    Returns (records, skipped, errors).
    """
    if adjudications is None:
        raise ValueError("adjudications are required; converter labels cannot be inferred")
    reviews_by_id = {item["id"]: item for item in adjudications}

    data = json.loads(pathlib.Path(eval_json_path).read_text())
    results_list = (
        data.get("results", {}).get("results", [])
        if isinstance(data.get("results"), dict)
        else data.get("results", [])
    )
    records = []
    skipped = []
    errors = []

    for i, r in enumerate(results_list):
        meta = r.get("metadata", {}) or {}
        strategy = meta.get("strategyId", "")
        if strategy not in ("goat", "crescendo"):
            skipped.append(f"test[{i}]: non-multi-turn strategy '{strategy}'")
            continue

        messages = meta.get("messages", [])
        if not messages:
            skipped.append(f"test[{i}]: no messages in metadata")
            continue

        # Extract only user (attacker) turns
        user_turns = [m for m in messages if m.get("role") == "user"]
        if len(user_turns) < min_user_turns:
            skipped.append(
                f"test[{i}]: only {len(user_turns)} user turns (need >= {min_user_turns})"
            )
            continue

        risk = _risk_category(meta)
        fam = _attack_family(meta)
        raw_id = f"{fam}_{i + record_index_offset}"
        record_id = deterministic_id(SRC_KEY, raw_id)
        review = reviews_by_id.get(record_id)
        if review is None:
            skipped.append(
                f"test[{i}]: {record_id} not selected for reviewed holdout"
            )
            continue

        # Build our multi-turn record from the user (attacker) turns
        our_turns = []
        for j, ut in enumerate(user_turns):
            content = str(ut.get("content", ""))
            if not content.strip():
                continue
            our_turns.append(make_turn("user", content, "user_direct", j))

        if not our_turns:
            skipped.append(f"test[{i}]: all user turns empty")
            continue

        rec = make_record(
            id=record_id,
            source_dataset=SRC_KEY,
            license="own",
            license_status="ok",
            modality="multi_turn",
            turns=our_turns,
            structured_action={
                "action_type": "unknown",
                "target_resource": None,
                "stated_purpose": None,
            },
            label={
                "risk_category": risk if review["is_malicious"] else "benign",
                "is_malicious": review["is_malicious"],
                "attack_family": fam if review["is_malicious"] else "benign",
                "purpose_capability_consistent": review[
                    "purpose_capability_consistent"
                ],
                "confidence": review["confidence"],
                "attack_stage_precursor": review["attack_stage_precursor"],
            },
            notes=(
                f"promptfoo {strategy} | plugin={meta.get('pluginId','?')} | "
                f"n_turns={len(user_turns)} | "
                f"stopReason={meta.get('stopReason','?')} | "
                f"attackSucceeded={bool(meta.get('successfulAttacks'))}"
            ),
        )
        errs = validate_record(rec)
        if errs:
            errors.append(f"{rec.get('id','?')}: {errs}")
            continue
        records.append(rec)

    selected_reviews = [reviews_by_id[record["id"]] for record in records]
    eval_path = pathlib.Path(eval_json_path)
    try:
        evidence_path = eval_path.resolve().relative_to(_REPO.resolve()).as_posix()
    except ValueError:
        evidence_path = eval_path.as_posix()
    source_evidence = match_source_evidence(
        records,
        [(evidence_path, data)],
    )
    reviewed = build_adjudications(records, selected_reviews, source_evidence)
    records = apply_adjudications(records, reviewed)
    if out_path:
        write_jsonl(pathlib.Path(out_path), records)
    return records, skipped, errors


def convert_many(eval_json_paths, out_path=None, min_user_turns=2, adjudications=None):
    """Convert ordered source files and require exact review-to-record coverage.

    Source order participates in the stable global result index used by record IDs.
    """
    if adjudications is None:
        raise ValueError("adjudications are required; converter labels cannot be inferred")

    records = []
    skipped = []
    errors = []
    record_index_offset = 0
    for eval_json_path in eval_json_paths:
        source_records, source_skipped, source_errors = convert(
            eval_json_path,
            min_user_turns=min_user_turns,
            adjudications=adjudications,
            record_index_offset=record_index_offset,
        )
        records.extend(source_records)
        skipped.extend(f"{eval_json_path}: {item}" for item in source_skipped)
        errors.extend(f"{eval_json_path}: {item}" for item in source_errors)
        source_data = json.loads(pathlib.Path(eval_json_path).read_text())
        source_results = (
            source_data.get("results", {}).get("results", [])
            if isinstance(source_data.get("results"), dict)
            else source_data.get("results", [])
        )
        record_index_offset += len(source_results)

    record_ids = [record["id"] for record in records]
    duplicate_ids = sorted(
        record_id for record_id in set(record_ids) if record_ids.count(record_id) > 1
    )
    review_ids = {item["id"] for item in adjudications}
    missing_reviews = sorted(set(record_ids) - review_ids)
    unused_reviews = sorted(review_ids - set(record_ids))
    if duplicate_ids or missing_reviews or unused_reviews:
        parts = []
        if duplicate_ids:
            parts.append(f"duplicate records: {', '.join(duplicate_ids)}")
        if missing_reviews:
            parts.append(f"missing reviews: {', '.join(missing_reviews)}")
        if unused_reviews:
            parts.append(f"unused reviews: {', '.join(unused_reviews)}")
        raise ValueError("; ".join(parts))

    if out_path:
        write_jsonl(pathlib.Path(out_path), records)
    return records, skipped, errors


def main():
    parser = argparse.ArgumentParser(
        description="Convert reviewed promptfoo multi-turn outputs to dataset JSONL."
    )
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("adjudications", type=pathlib.Path)
    parser.add_argument(
        "eval_sources",
        nargs="+",
        type=pathlib.Path,
        help="eval files in canonical order; order participates in stable record IDs",
    )
    args = parser.parse_args()

    adjudications = json.loads(args.adjudications.read_text())
    records, skipped, errors = convert_many(
        args.eval_sources,
        args.output,
        adjudications=adjudications,
    )
    from collections import Counter
    fams = Counter(r["label"]["attack_family"] for r in records)
    print(f"converted {len(records)} multi-turn records -> {args.output}", file=sys.stderr)
    for f, c in fams.most_common():
        print(f"  {f}: {c}", file=sys.stderr)
    if skipped:
        print(f"skipped: {len(skipped)} (first 3): {skipped[:3]}", file=sys.stderr)
    if errors:
        print(f"errors: {len(errors)} (first 3): {errors[:3]}", file=sys.stderr)


if __name__ == "__main__":
    main()
