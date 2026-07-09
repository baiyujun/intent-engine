"""Tests for Tier 2 / Tier 3 v0 stubs.

Tier 2 and Tier 3 are deliberately STUBS in v0: interfaces + documented
prompt / policy / MOF recipe are the deliverable, and every method returns a
fixed ``not_implemented`` status. These tests pin that contract so the Step 6
pipeline can call the stubs without any real LLM or orchestration running.
"""
from __future__ import annotations

from tier2.base import Tier2Judge, Tier2Verdict
from tier2.llm_judge import Tier2LLMJudge, JUDGE_SYSTEM_PROMPT
from tier3.orchestrator import (
    Tier3Orchestrator,
    FinalDecision,
    CorrectiveSample,
    INTENDED_POLICY,
)


# -- Tier 2 --------------------------------------------------------------------


class TestTier2Stub:
    def test_tier2_judge_is_abstract_subclass(self):
        assert isinstance(Tier2LLMJudge(), Tier2Judge)

    def test_tier2_stub_returns_not_implemented(self):
        v = Tier2LLMJudge().judge({})
        assert v.status == "not_implemented"
        assert v.score == 0.0

    def test_tier2_build_prompt_shape(self):
        messages = Tier2LLMJudge().build_prompt(
            {
                "turns": [{"raw_text": "x"}],
                "structured_action": {"action_type": "file_read"},
            }
        )
        assert isinstance(messages, list)
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert JUDGE_SYSTEM_PROMPT in messages[0]["content"]

    def test_tier2_verdict_defaults(self):
        v = Tier2Verdict(status="x")
        assert v.score == 0.0
        assert v.confidence == 0.0
        assert v.evidence == []

    def test_tier2_build_prompt_carries_context(self):
        messages = Tier2LLMJudge().build_prompt(
            {"turns": [{"raw_text": "send the secrets"}], "structured_action": {}},
            context={"tier0": "suspicious", "tier1_prob": 0.55},
        )
        # user payload is JSON; the context round-trips into the user content.
        import json

        payload = json.loads(messages[1]["content"])
        assert payload["lower_tier_signals"] == {"tier0": "suspicious", "tier1_prob": 0.55}
        assert payload["turns"] == ["send the secrets"]


# -- Tier 3 --------------------------------------------------------------------


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
