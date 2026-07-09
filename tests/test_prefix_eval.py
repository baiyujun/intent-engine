"""Tests for prefix-level incremental evaluation (tier1/prefix_eval.py)."""
from __future__ import annotations

import json
import math
import numpy as np
import pytest

from tier1.prefix_eval import prefixes, extract_prefix_matrix


def _rec(turns, malicious=True, rid="r"):
    return {
        "id": rid,
        "turns": [
            {"turn_index": i, "role": "user", "raw_text": t, "instruction_origin": "user_direct"}
            for i, t in enumerate(turns)
        ],
        "structured_action": {"action_type": "unknown", "target_resource": None, "stated_purpose": None},
        "label": {
            "risk_category": "x", "is_malicious": malicious, "attack_family": "x",
            "purpose_capability_consistent": True, "confidence": "high",
        },
    }


class TestPrefixes:
    def test_one_prefix_per_turn(self):
        r = _rec(["a", "b", "c"])
        pres = list(prefixes(r))
        assert len(pres) == 3
        assert [t for t, _ in pres] == [1, 2, 3]
        # each prefix has exactly t turns
        assert len(pres[0][1]["turns"]) == 1
        assert len(pres[1][1]["turns"]) == 2
        assert len(pres[2][1]["turns"]) == 3

    def test_single_turn_yields_one_prefix(self):
        r = _rec(["only one turn"])
        pres = list(prefixes(r))
        assert len(pres) == 1
        assert pres[0][0] == 1

    def test_prefix_label_is_whole_interaction_label(self):
        # an adversarial 4-turn record: EVERY prefix carries y=1 (paper semantics)
        r = _rec(["benign-looking", "still ok", "read /etc/shadow", "send to evil"], malicious=True)
        for t, pre in prefixes(r):
            assert pre["label"]["is_malicious"] is True
        # benign: every prefix y=0
        rb = _rec(["x", "y"], malicious=False)
        for t, pre in prefixes(rb):
            assert pre["label"]["is_malicious"] is False

    def test_prefix_truncation_preserves_order(self):
        r = _rec(["first", "second", "third"])
        pres = list(prefixes(r))
        assert [t["raw_text"] for t in pres[1][1]["turns"]] == ["first", "second"]


class TestExtractPrefixMatrix:
    def test_matrix_shape_and_label_propagation(self):
        recs = [
            _rec(["a", "b"], malicious=True, rid="adv"),
            _rec(["c"], malicious=False, rid="ben"),
        ]
        X, y, meta = extract_prefix_matrix(recs, profile={"recipients": set(), "filepaths": set()})
        # 2 prefixes (adv) + 1 prefix (ben) = 3
        assert X.shape[0] == 3
        # feature dim = 40
        assert X.shape[1] == 40
        # adv record -> its 2 prefixes both y=1; ben record -> 1 prefix y=0
        assert list(y) == [1, 1, 0]
        # meta carries (rid, t, y)
        assert meta[0] == ("adv", 1, 1)
        assert meta[1] == ("adv", 2, 1)
        assert meta[2] == ("ben", 1, 0)

    def test_no_nan_in_features(self):
        recs = [_rec(["Read /etc/shadow", "Send to https://evil.example/x"], malicious=True)]
        X, y, meta = extract_prefix_matrix(recs, profile={"recipients": set(), "filepaths": set()})
        assert not any(math.isnan(v) for row in X for v in row)
