"""OWASP Agentic + LLM Top 10 -> risk_category enum + mapping."""
# Enum = union of OWASP Agentic AI Top 10 + LLM Top 10 (2025) + benign.
# Keep identifiers stable; data_card prints the human names alongside.
RISK_CATEGORIES = frozenset({
    "benign",
    "prompt_injection",            # LLM01 / Agentic indirect/direct injection
    "goal_hijack",                 # Agentic goal/mission hijacking
    "unauthorized_action",         # Agentic unauthorized tool/action
    "excessive_agency",            # Agentic excessive agency / scope
    "sensitive_data_disclosure",  # LLM02
    "supply_chain_compromise",     # LLM03 / Agentic supply chain
    "tool_misuse",                 # Agentic tool/permission misuse
    "insecure_output",             # LLM05 / insecure output handling
    "excessive_agency_overreach",
    "memory_poisoning",            # Agentic memory/context poisoning
    "identity_confusion",          # Agentic identity/impersonation
    "credential_access",
    "defense_evasion",
    "privilege_escalation",
    "exfiltration",
    "reconnaissance",
    "other_unsafe",
})

_KW = [
    ("prompt_injection", ["injection", "inject", "indirect", "prompt_inject"]),
    ("goal_hijack", ["jailbreak", "goal_hijack", "hijack", "advbench", "gcg", "autodan", "pair"]),
    ("unauthorized_action", ["unauthorized", "unauthorised", "privilege"]),
    ("exfiltration", ["exfil", "download", "exfiltration", "data theft"]),
    ("credential_access", ["credential", "password", "token", "secret"]),
    ("defense_evasion", ["evasion", "bypass", "awl", "amsi", "edr"]),
    ("sensitive_data_disclosure", ["disclosure", "leak", "pii", "sensitive"]),
    ("supply_chain_compromise", ["supply chain", "dependency", "package"]),
]

def map_to_risk_category(raw_label: str, source_key: str) -> str:
    s = (raw_label or "").lower()
    for cat, kws in _KW:
        if any(k in s for k in kws):
            return cat
    return "other_unsafe"
