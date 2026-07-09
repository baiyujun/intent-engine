"""Tier 0 dual-path deterministic judge.

Public API:
    judge()          — top-level judge combining rule engine + vector retrieval + fusion
    fuse()           — combine a RuleVerdict + VectorVerdict into a Tier0Verdict
    Tier0Verdict     — final verdict dataclass with escalation flag + timing
"""
from .fusion import judge, fuse, Tier0Verdict  # noqa: F401

