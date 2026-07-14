import json

from tier1.eval_data import load_multiturn_holdout


def _write_jsonl(path, records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def test_load_multiturn_holdout_counts_mixed_reviewed_labels(tmp_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    _write_jsonl(
        processed / "test_holdout_multiturn.jsonl",
        [
            {"id": "reviewed-mal", "label": {"is_malicious": True}},
            {"id": "reviewed-ben", "label": {"is_malicious": False}},
        ],
    )
    _write_jsonl(
        processed / "test_holdout_multiturn_benign.jsonl",
        [{"id": "legacy-ben", "label": {"is_malicious": False}}],
    )

    holdout = load_multiturn_holdout(tmp_path)

    assert [record["id"] for record in holdout["reviewed"]] == [
        "reviewed-mal",
        "reviewed-ben",
    ]
    assert [record["id"] for record in holdout["malicious"]] == ["reviewed-mal"]
    assert [record["id"] for record in holdout["benign"]] == [
        "reviewed-ben",
        "legacy-ben",
    ]
    assert holdout["counts"] == {
        "reviewed": 2,
        "legacy_benign": 1,
        "malicious": 1,
        "benign": 2,
        "total": 3,
    }
