from src.licenses import license_status, license_spdx, can_enter_training, load_license_config

def test_agentdojo_ok():
    assert license_status("agentdojo") == "ok"
    assert license_spdx("agentdojo") == "MIT"
    assert can_enter_training("agentdojo") is True

def test_bipia_needs_confirmation():
    assert license_status("bipia") == "needs_confirmation"
    assert can_enter_training("bipia") is False

def test_rjudge_needs_confirmation():
    assert license_status("rjudge") == "needs_confirmation"

def test_unknown_key_excluded():
    assert license_status("does_not_exist") == "excluded"
    assert can_enter_training("does_not_exist") is False

def test_gtfobins_gpl_ok():
    assert license_status("gtfobins") == "ok"
    assert "GPL" in (license_spdx("gtfobins") or "")
