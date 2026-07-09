"""Tests for tier0.fusion — agreement/disagreement/fuzzy fusion logic."""
from __future__ import annotations

import pytest

from tier0.fusion import fuse, FUZZY_LOW, FUZZY_HIGH, Tier0Verdict
from tier0.rule_engine import RuleVerdict
from tier0.vector_index import VectorVerdict


def _rule(risk: str, d1=0, d2=0, d3=0, sc=None) -> RuleVerdict:
    return RuleVerdict(risk_level=risk, d1=d1, d2=d2, d3=d3, matched_patterns=[], short_circuit=sc)


def _vec(margin: float, d_ben=1.0, d_mal=1.0) -> VectorVerdict:
    return VectorVerdict(d_benign=d_ben, d_malicious=d_mal, margin=margin, nearest_benign_id="b", nearest_malicious_id="m")


class TestAgreement:
    def test_agree_benign(self):
        v = fuse(_rule("low"), _vec(margin=0.5))
        assert v.escalated is False
        assert v.final_verdict == "benign"

    def test_agree_malicious(self):
        v = fuse(_rule("critical"), _vec(margin=-0.5))
        assert v.escalated is False
        assert v.final_verdict == "malicious"

    def test_rule_suspicious_vector_malicious(self):
        v = fuse(_rule("medium"), _vec(margin=-0.5))
        assert v.escalated is False
        assert v.final_verdict == "suspicious"


class TestDisagreement:
    def test_rule_high_vector_benign(self):
        v = fuse(_rule("critical"), _vec(margin=0.5))
        assert v.escalated is True
        assert v.final_verdict == "suspicious"
        assert any("conflict" in r for r in v.escalation_reasons)

    def test_rule_low_vector_malicious(self):
        v = fuse(_rule("low"), _vec(margin=-0.5))
        assert v.escalated is True
        assert v.final_verdict == "suspicious"
        assert any("conflict" in r for r in v.escalation_reasons)

    def test_rule_suspicious_vector_benign(self):
        v = fuse(_rule("medium"), _vec(margin=0.5))
        assert v.escalated is True
        assert v.final_verdict == "suspicious"


class TestFuzzyZone:
    def test_fuzzy_zone_escalates(self):
        # margin exactly inside the fuzzy band
        v = fuse(_rule("critical"), _vec(margin=0.0))
        assert v.escalated is True
        assert v.final_verdict == "suspicious"

    def test_fuzzy_boundary_low_not_fuzzy(self):
        # margin just outside fuzzy_low (more negative) → malicious direction
        v = fuse(_rule("low"), _vec(margin=FUZZY_LOW - 0.01))
        assert v.escalated is True  # rule benign vs vector malicious

    def test_fuzzy_boundary_high_not_fuzzy(self):
        # margin just outside fuzzy_high (more positive) → benign direction
        v = fuse(_rule("critical"), _vec(margin=FUZZY_HIGH + 0.01))
        assert v.escalated is True  # rule malicious vs vector benign


class TestVerdictFields:
    def test_carries_rule_fields(self):
        v = fuse(_rule("high", d1=3, d2=2, d3=1, sc="SC-1"), _vec(margin=-0.5))
        assert v.rule_risk == "high"
        assert v.rule_d1 == 3
        assert v.rule_d2 == 2
        assert v.rule_d3 == 1
        assert v.rule_short_circuit == "SC-1"

    def test_carries_vector_fields(self):
        v = fuse(_rule("low"), _vec(margin=0.3, d_ben=0.2, d_mal=0.5))
        assert v.vector_margin == pytest.approx(0.3)
        assert v.vector_d_benign == pytest.approx(0.2)
        assert v.vector_d_malicious == pytest.approx(0.5)
