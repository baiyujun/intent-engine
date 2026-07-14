import json
from pathlib import Path

import pytest

import synth.multiturn_convert as multiturn_convert
from synth.multiturn_convert import convert
from synth.multiturn_relabel import (
    apply_adjudications,
    build_adjudications,
    match_source_evidence,
)


def test_apply_adjudications_replaces_hardcoded_label_and_keeps_provenance():
    record = {
        "id": "promptfoo_multiturn_crescendo_coding-agent_repo-prompt-injection_126",
        "label": {
            "risk_category": "exfiltration",
            "is_malicious": True,
            "attack_family": "crescendo_coding-agent_repo-prompt-injection",
            "purpose_capability_consistent": False,
            "confidence": "high",
            "attack_stage_precursor": False,
        },
    }
    adjudication = {
        "id": record["id"],
        "label": {
            "risk_category": "benign",
            "is_malicious": False,
            "attack_family": "benign",
            "purpose_capability_consistent": True,
            "confidence": "high",
            "attack_stage_precursor": False,
        },
        "source_evidence": {
            "eval_file": "synth/multiturn_eval.json",
            "result_index": 126,
            "grader_status": "pass",
        },
        "rationale": "Visible turns are informational questions and propose no unsafe action.",
    }

    [relabeled] = apply_adjudications([record], [adjudication])

    assert relabeled["label"] == adjudication["label"]
    assert relabeled["label_provenance"] == {
        "method": "visible_action_plus_source_grader",
        "source_evidence": adjudication["source_evidence"],
        "rationale": adjudication["rationale"],
    }
    assert record["label"]["is_malicious"] is True


def test_apply_adjudications_requires_exact_record_coverage():
    records = [
        {"id": "record-a", "label": {"is_malicious": True}},
        {"id": "record-b", "label": {"is_malicious": True}},
    ]
    adjudications = [
        {
            "id": "record-a",
            "label": {"is_malicious": False},
            "source_evidence": {"grader_status": "pass"},
            "rationale": "No unsafe visible action.",
        },
        {
            "id": "unknown-record",
            "label": {"is_malicious": True},
            "source_evidence": {"grader_status": "fail"},
            "rationale": "Not part of this holdout.",
        },
    ]

    with pytest.raises(
        ValueError,
        match="missing adjudications: record-b; unknown adjudications: unknown-record",
    ):
        apply_adjudications(records, adjudications)


def test_match_source_evidence_joins_on_complete_visible_user_turns():
    records = [
        {
            "id": "record-a",
            "turns": [
                {"role": "user", "raw_text": "First request"},
                {"role": "user", "raw_text": "Second request"},
            ],
        }
    ]
    source_data = {
        "results": {
            "results": [
                {
                    "metadata": {
                        "messages": [
                            {"role": "user", "content": "First request"},
                            {"role": "assistant", "content": "Response"},
                            {"role": "user", "content": "Second request"},
                        ],
                        "storedGraderResult": {
                            "pass": False,
                            "reason": "The response performed the forbidden action.",
                        },
                        "stopReason": "Grader failed",
                        "successfulAttacks": [{"turn": 2}],
                    }
                }
            ]
        }
    }

    evidence = match_source_evidence(
        records,
        [("synth/example_eval.json", source_data)],
    )

    assert evidence == {
        "record-a": {
            "eval_file": "synth/example_eval.json",
            "result_index": 0,
            "grader_status": "fail",
            "grader_reason": "The response performed the forbidden action.",
            "stop_reason": "Grader failed",
            "successful_attacks": True,
        }
    }


def test_converter_refuses_to_emit_unadjudicated_labels(tmp_path):
    eval_path = tmp_path / "eval.json"
    eval_path.write_text(
        json.dumps(
            {
                "results": {
                    "results": [
                        {
                            "metadata": {
                                "strategyId": "goat",
                                "pluginId": "coding-agent:secret-file-read",
                                "messages": [
                                    {"role": "user", "content": "First request"},
                                    {"role": "assistant", "content": "Response"},
                                    {"role": "user", "content": "Second request"},
                                ],
                            }
                        }
                    ]
                }
            }
        )
    )

    with pytest.raises(ValueError, match="adjudications are required"):
        convert(eval_path)


def test_converter_builds_label_and_provenance_from_review_manifest(tmp_path):
    eval_path = tmp_path / "eval.json"
    eval_path.write_text(
        json.dumps(
            {
                "results": {
                    "results": [
                        {
                            "metadata": {
                                "strategyId": "goat",
                                "pluginId": "coding-agent:secret-file-read",
                                "messages": [
                                    {"role": "user", "content": "First request"},
                                    {"role": "assistant", "content": "Response"},
                                    {"role": "user", "content": "Second request"},
                                ],
                                "storedGraderResult": {
                                    "pass": False,
                                    "reason": "The response performed the forbidden action.",
                                },
                            }
                        }
                    ]
                }
            }
        )
    )
    review = {
        "id": "promptfoo_multiturn_goat_coding-agent_secret-file-read_0",
        "is_malicious": True,
        "purpose_capability_consistent": False,
        "confidence": "high",
        "attack_stage_precursor": False,
        "rationale": "The visible request asks for a sensitive-file read.",
    }

    records, skipped, errors = convert(eval_path, adjudications=[review])

    assert skipped == []
    assert errors == []
    assert records[0]["label"]["is_malicious"] is True
    assert records[0]["label_provenance"]["source_evidence"]["grader_status"] == "fail"
    assert records[0]["label_provenance"]["rationale"] == review["rationale"]


def test_converter_combines_multiple_sources_with_exact_review_coverage(tmp_path):
    eval_paths = []
    reviews = []
    for source_index, plugin in enumerate(
        ("coding-agent:secret-file-read", "coding-agent:network-egress-bypass")
    ):
        eval_path = tmp_path / f"eval-{source_index}.json"
        source_results = [
            {
                "metadata": {
                    "strategyId": "goat",
                    "pluginId": plugin,
                    "messages": [
                        {"role": "user", "content": f"First {source_index}"},
                        {"role": "user", "content": f"Second {source_index}"},
                    ],
                }
            }
        ]
        if source_index == 0:
            source_results.append(
                {
                    "metadata": {
                        "strategyId": "goat",
                        "pluginId": plugin,
                        "messages": [
                            {"role": "user", "content": "Unselected first"},
                            {"role": "user", "content": "Unselected second"},
                        ],
                    }
                }
            )
        eval_path.write_text(
            json.dumps(
                {
                    "results": {
                        "results": source_results
                    }
                }
            )
        )
        eval_paths.append(eval_path)
        reviews.append(
            {
                "id": (
                    f"promptfoo_multiturn_goat_{plugin.replace(':', '_')}_"
                    f"{0 if source_index == 0 else 2}"
                ),
                "is_malicious": True,
                "purpose_capability_consistent": False,
                "confidence": "high",
                "attack_stage_precursor": False,
                "rationale": "The visible request asks for an unsafe operation.",
            }
        )

    records, skipped, errors = multiturn_convert.convert_many(
        eval_paths,
        adjudications=reviews,
    )

    assert len(records) == 2
    assert len(skipped) == 1
    assert "not selected for reviewed holdout" in skipped[0]
    assert errors == []
    assert {record["id"] for record in records} == {review["id"] for review in reviews}


def test_canonical_sources_rebuild_committed_reviewed_holdout():
    repo = Path(__file__).resolve().parents[1]
    reviews = json.loads(
        (repo / "synth" / "multiturn_adjudication_20260714.json").read_text()
    )
    committed = [
        json.loads(line)
        for line in (
            repo / "dataset" / "processed" / "test_holdout_multiturn.jsonl"
        ).read_text().splitlines()
        if line.strip()
    ]

    rebuilt, _, errors = multiturn_convert.convert_many(
        [
            repo / "synth" / "multiturn_eval.json",
            repo / "synth" / "multiturn_supplement_eval.json",
        ],
        adjudications=reviews,
    )

    assert errors == []
    assert rebuilt == committed


def test_build_adjudications_resets_benign_taxonomy_and_attaches_source_evidence():
    record = {
        "id": "record-a",
        "label": {
            "risk_category": "exfiltration",
            "is_malicious": True,
            "attack_family": "goat_secret-file-read",
            "purpose_capability_consistent": False,
            "confidence": "high",
            "attack_stage_precursor": False,
        },
    }
    review = {
        "id": "record-a",
        "is_malicious": False,
        "purpose_capability_consistent": True,
        "confidence": "high",
        "attack_stage_precursor": True,
        "rationale": "The visible request is defensive and proposes no unsafe action.",
    }
    source_evidence = {
        "record-a": {
            "eval_file": "synth/example_eval.json",
            "result_index": 7,
            "grader_status": "fail",
        }
    }

    [adjudication] = build_adjudications([record], [review], source_evidence)

    assert adjudication["label"] == {
        "risk_category": "benign",
        "is_malicious": False,
        "attack_family": "benign",
        "purpose_capability_consistent": True,
        "confidence": "high",
        "attack_stage_precursor": True,
    }
    assert adjudication["source_evidence"] == source_evidence["record-a"]


def test_build_adjudications_rejects_incomplete_review_manifest():
    records = [
        {"id": "record-a", "label": {"is_malicious": True}},
        {"id": "record-b", "label": {"is_malicious": True}},
    ]
    reviews = [
        {
            "id": "record-a",
            "is_malicious": True,
            "purpose_capability_consistent": False,
            "confidence": "high",
            "attack_stage_precursor": False,
            "rationale": "Visible action is unsafe.",
        },
        {
            "id": "unknown-record",
            "is_malicious": False,
            "purpose_capability_consistent": True,
            "confidence": "high",
            "attack_stage_precursor": False,
            "rationale": "Not part of this holdout.",
        },
    ]

    with pytest.raises(
        ValueError,
        match="missing reviews: record-b; unknown reviews: unknown-record",
    ):
        build_adjudications(records, reviews, {})
