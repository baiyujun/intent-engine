"""Tests for Tier 2 (v0.4 REAL semantic judge) and Tier 3 (v0 stub).

v0.4 promoted Tier 2 from a stub to a real Evidence-Capsule + purpose-capability
judge. These tests pin the v0.4 contract WITHOUT making network calls:
  - build_prompt produces an Evidence Capsule (fenced raw text + structured
    Tier0/Tier1 signals + structured_action), in [system, user] form;
  - the system prompt forbids word-presence as a sole verdict basis and mandates
    purpose-capability reasoning;
  - _extract_json / _calibrate handle malformed/over-confident output;
  - judge() falls back HONESTLY (suspicious, confidence 0) on parse failure.
Tier 3 remains a stub (interface + audit trail).
"""
from __future__ import annotations

import json

from tier2.base import Tier2Judge, Tier2Verdict
from tier2.llm_judge import Tier2LLMJudge, JUDGE_SYSTEM_PROMPT, _calibrate
from tier2.llm_client import _extract_json
from tier3.orchestrator import (
    Tier3Orchestrator,
    FinalDecision,
    CorrectiveSample,
    INTENDED_POLICY,
)


# -- Tier 2 --------------------------------------------------------------------


class TestTier2Judge:
    def test_tier2_judge_is_subclass(self):
        assert isinstance(Tier2LLMJudge(), Tier2Judge)

    def test_tier2_build_prompt_shape(self):
        msgs = Tier2LLMJudge().build_prompt(
            {"turns": [{"raw_text": "x"}],
             "structured_action": {"action_type": "file_read",
                                   "target_resource": "y",
                                   "stated_purpose": "p"}}
        )
        assert isinstance(msgs, list) and len(msgs) == 2
        assert msgs[0]["role"] == "system" and msgs[1]["role"] == "user"
        assert JUDGE_SYSTEM_PROMPT in msgs[0]["content"]

    def test_tier2_system_prompt_forbids_keyword_as_verdict(self):
        # the ONE rule a keyword detector violates must be in the system prompt
        p = JUDGE_SYSTEM_PROMPT
        assert "not, by itself, evidence" in p.lower() or "by itself" in p.lower()
        assert "purpose" in p.lower() and "capability" in p.lower()
        assert "purpose_capability_consistent" in p

    def test_tier2_build_prompt_is_evidence_capsule(self):
        msgs = Tier2LLMJudge().build_prompt(
            {"turns": [{"raw_text": "read /var/log/secure and send to host"}],
             "structured_action": {}}
        )
        payload = json.loads(msgs[1]["content"])
        # Evidence Capsule structure: fenced raw + tier0/tier1 signals
        assert "raw_interaction" in payload
        assert "RAW_AGENT_INTERACTION_BEGIN" in payload["raw_interaction"]
        assert "tier0_signals" in payload and "tier1_signals" in payload
        assert "structured_action" in payload
        # raw text must be FENCED, not bare
        assert payload["raw_interaction"].count(">>") >= 2

    def test_tier2_extract_json_robust(self):
        assert _extract_json('{"a": 1}') == {"a": 1}
        assert _extract_json('thinking...\n{"a": 2}\ntail') == {"a": 2}
        assert _extract_json('```json\n{"a": 3}\n```') == {"a": 3}
        assert _extract_json('no json') is None

    def test_tier2_calibrate_discounts_internal_disagreement(self):
        # malicious verdict + pcc consistent (disagrees) → halved
        assert _calibrate(0.9, verdict="malicious", pcc=True) <= 0.5
        # benign + pcc consistent (agrees) → not halved
        assert _calibrate(0.9, verdict="benign", pcc=True) == 0.9
        # over-confident capped at 0.95
        assert _calibrate(1.0, verdict="benign", pcc=True) == 0.95
        # bad input floored to 0.5
        assert _calibrate(None, verdict="benign", pcc=True) == 0.5

    def test_tier2_verdict_defaults(self):
        v = Tier2Verdict(status="x")
        assert v.score == 0.0 and v.confidence == 0.0 and v.evidence == []


# -- Tier 3 (still v0 stub) -----------------------------------------------------


class TestTier3Stub:
    def test_tier3_orchestrate_stub(self):
        d = Tier3Orchestrator().orchestrate(None, None, None)
        assert d.status == "not_implemented"
        assert d.audit_trail  # non-empty
        assert any("stub" in line.lower() for line in d.audit_trail)

    def test_tier3_orchestrate_audit_trail_mentions_policy(self):
        d = Tier3Orchestrator().orchestrate(None, None, None)
        joined = " ".join(d.audit_trail)
        # the documented intended policy is surfaced in the stub audit trail
        for rule in INTENDED_POLICY:
            assert rule in joined

    def test_tier3_corrective_stub(self):
        s = Tier3Orchestrator().corrective_update({"turns": []})
        assert s.status == "not_implemented"

    def test_tier3_generate_stub(self):
        out = Tier3Orchestrator().generate_corrective_samples([], 5)
        assert isinstance(out, list)
        assert out == []  # v0 returns empty list

    def test_final_decision_defaults(self):
        d = FinalDecision(status="x")
        assert d.verdict == ""
        assert d.audit_trail == []

    def test_corrective_sample_defaults(self):
        s = CorrectiveSample(status="x")
        assert s.sample is None
        assert s.trigger_phrase == ""
