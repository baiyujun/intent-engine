"""Apply independently reviewed labels to promptfoo multi-turn records."""

import argparse
import json
from copy import deepcopy
from pathlib import Path


def match_source_evidence(records, eval_sources):
    """Match records to promptfoo results by their complete visible user-turn sequence."""
    candidates = {}
    for eval_file, data in eval_sources:
        results = data.get("results", {}).get("results", [])
        for result_index, result in enumerate(results):
            metadata = result.get("metadata", {}) or {}
            user_turns = tuple(
                str(message.get("content", ""))
                for message in metadata.get("messages", [])
                if message.get("role") == "user"
                and str(message.get("content", "")).strip()
            )
            if not user_turns:
                continue
            grader = metadata.get("storedGraderResult")
            if isinstance(grader, dict) and grader.get("pass") is True:
                grader_status = "pass"
            elif isinstance(grader, dict) and grader.get("pass") is False:
                grader_status = "fail"
            else:
                grader_status = "missing"
            candidates.setdefault(user_turns, []).append(
                {
                    "eval_file": eval_file,
                    "result_index": result_index,
                    "grader_status": grader_status,
                    "grader_reason": grader.get("reason") if isinstance(grader, dict) else None,
                    "stop_reason": metadata.get("stopReason"),
                    "successful_attacks": bool(metadata.get("successfulAttacks")),
                }
            )

    evidence = {}
    for record in records:
        visible_turns = tuple(
            str(turn.get("raw_text", ""))
            for turn in record.get("turns", [])
            if turn.get("role") == "user" and str(turn.get("raw_text", "")).strip()
        )
        matches = candidates.get(visible_turns, [])
        if len(matches) != 1:
            raise ValueError(
                f"expected one source match for {record['id']}, found {len(matches)}"
            )
        evidence[record["id"]] = matches[0]
    return evidence


def build_adjudications(records, reviews, source_evidence):
    """Combine human visible-action reviews with matched source grader evidence."""
    reviews_by_id = {item["id"]: item for item in reviews}
    record_ids = {record["id"] for record in records}
    review_ids = set(reviews_by_id)
    missing = sorted(record_ids - review_ids)
    unknown = sorted(review_ids - record_ids)
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing reviews: {', '.join(missing)}")
        if unknown:
            parts.append(f"unknown reviews: {', '.join(unknown)}")
        raise ValueError("; ".join(parts))

    adjudications = []
    for record in records:
        review = reviews_by_id[record["id"]]
        label = deepcopy(record["label"])
        label.update(
            {
                "is_malicious": review["is_malicious"],
                "purpose_capability_consistent": review[
                    "purpose_capability_consistent"
                ],
                "confidence": review["confidence"],
                "attack_stage_precursor": review["attack_stage_precursor"],
            }
        )
        if not review["is_malicious"]:
            label["risk_category"] = "benign"
            label["attack_family"] = "benign"
        adjudications.append(
            {
                "id": record["id"],
                "label": label,
                "source_evidence": deepcopy(source_evidence[record["id"]]),
                "rationale": review["rationale"],
            }
        )
    return adjudications


def apply_adjudications(records, adjudications):
    """Return relabeled copies with the review evidence attached."""
    by_id = {item["id"]: item for item in adjudications}
    record_ids = {record["id"] for record in records}
    adjudication_ids = set(by_id)
    missing = sorted(record_ids - adjudication_ids)
    unknown = sorted(adjudication_ids - record_ids)
    if missing or unknown:
        parts = []
        if missing:
            parts.append(f"missing adjudications: {', '.join(missing)}")
        if unknown:
            parts.append(f"unknown adjudications: {', '.join(unknown)}")
        raise ValueError("; ".join(parts))

    relabeled = []
    for record in records:
        item = by_id[record["id"]]
        updated = deepcopy(record)
        updated["label"] = deepcopy(item["label"])
        updated["label_provenance"] = {
            "method": "visible_action_plus_source_grader",
            "source_evidence": deepcopy(item["source_evidence"]),
            "rationale": item["rationale"],
        }
        relabeled.append(updated)
    return relabeled


def relabel_records(records, reviews, eval_sources):
    """Build source-backed adjudications and apply them to record copies."""
    source_evidence = match_source_evidence(records, eval_sources)
    adjudications = build_adjudications(records, reviews, source_evidence)
    return apply_adjudications(records, adjudications)


def _read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _write_jsonl(path, records):
    path.write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records))


def main():
    parser = argparse.ArgumentParser(
        description="Relabel promptfoo multi-turn records from reviewed visible actions."
    )
    parser.add_argument("records", type=Path)
    parser.add_argument("reviews", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("eval_sources", nargs="+", type=Path)
    args = parser.parse_args()

    records = _read_jsonl(args.records)
    reviews = json.loads(args.reviews.read_text())
    eval_sources = [
        (str(path), json.loads(path.read_text())) for path in args.eval_sources
    ]
    relabeled = relabel_records(records, reviews, eval_sources)
    _write_jsonl(args.output, relabeled)
    print(f"relabeled {len(relabeled)} records -> {args.output}")


if __name__ == "__main__":
    main()
