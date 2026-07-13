"""Tier 3 — final orchestration + MOF corrective feedback + read-only investigation.

Public API:
    Tier3Orchestrator  — combines tier verdicts into a final decision; generates
                         MOF corrective samples on false negatives (orchestration/MOF stub)
    FinalDecision      — final allow / block / escalate decision + audit trail
    CorrectiveSample   — a benign corrective sample produced by MOF feedback

    ReadOnlyToolkit            — read-only investigation facade (v0.5 Part 4); NO write/exec methods
    ReadOnlyToolkitBackend     — abstract read-only backend (3 read methods only)
    FixtureToolkitBackend      — synthetic in-memory test-fixture backend (labeled, not real)
    Tier3Investigator          — resolves Tier2 information_gaps via read-only queries + a rule
    Tier3Verdict               — result of a Tier3 investigation
"""
from .orchestrator import Tier3Orchestrator, FinalDecision, CorrectiveSample
from .read_only_toolkit import (
    ReadOnlyToolkit, ReadOnlyToolkitBackend, FixtureToolkitBackend,
    TrajectoryResult, CodebaseResult, InfraResult,
)
from .investigator import Tier3Investigator, Tier3Verdict

__all__ = [
    "Tier3Orchestrator", "FinalDecision", "CorrectiveSample",
    "ReadOnlyToolkit", "ReadOnlyToolkitBackend", "FixtureToolkitBackend",
    "TrajectoryResult", "CodebaseResult", "InfraResult",
    "Tier3Investigator", "Tier3Verdict",
]
