from src.owasp_taxonomy import RISK_CATEGORIES, map_to_risk_category

def test_benign_present():
    assert "benign" in RISK_CATEGORIES

def test_prompt_injection_maps():
    assert map_to_risk_category("prompt injection", "deepset") == "prompt_injection"

def test_jailbreak_maps_to_goal_hijack():
    assert map_to_risk_category("jailbreak", "jailbreakbench") in {"goal_hijack", "prompt_injection"}

def test_unknown_maps_to_other():
    assert map_to_risk_category("some weird thing", "x").startswith(("other_", "unauthorized"))
