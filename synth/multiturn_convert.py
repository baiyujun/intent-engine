"""Convert promptfoo GOAT/Crescendo multi-turn eval output → dataset-schema records.

Extracts the conversation `messages` from each GOAT/Crescendo test result,
keeps only the user (attacker) turns as our multi-turn record's turns,
and stores the full conversation metadata in notes for traceability.

This module is the GLUE between promptfoo's real multi-turn generation engine
and our v0 dataset schema. It does NOT generate any content itself — promptfoo
does that via GOAT/Crescendo live evaluation.
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


def convert(eval_json_path, out_path=None, min_user_turns=2):
    """Read promptfoo multi-turn eval output, emit schema-valid malicious records.

    Only keeps conversations with >= min_user_turns user (attacker) turns
    to ensure genuine multi-turn attack chains.

    Returns (records, skipped, errors).
    """
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
        raw_id = f"{fam}_{i}"

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
            _raw_id=raw_id,
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
                "risk_category": risk,
                "is_malicious": True,
                "attack_family": fam,
                "purpose_capability_consistent": False,
                "confidence": "high",
                "attack_stage_precursor": False,
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

    if out_path:
        write_jsonl(pathlib.Path(out_path), records)
    return records, skipped, errors


def main():
    here = pathlib.Path(__file__).resolve().parent
    eval_path = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else here / "multiturn_eval.json"
    )
    out_path = pathlib.Path(
        sys.argv[2] if len(sys.argv) > 2
        else _REPO / "dataset" / "processed" / "test_holdout_multiturn.jsonl"
    )
    records, skipped, errors = convert(eval_path, out_path)
    from collections import Counter
    fams = Counter(r["label"]["attack_family"] for r in records)
    print(f"converted {len(records)} multi-turn records -> {out_path}", file=sys.stderr)
    for f, c in fams.most_common():
        print(f"  {f}: {c}", file=sys.stderr)
    if skipped:
        print(f"skipped: {len(skipped)} (first 3): {skipped[:3]}", file=sys.stderr)
    if errors:
        print(f"errors: {len(errors)} (first 3): {errors[:3]}", file=sys.stderr)


if __name__ == "__main__":
    main()
