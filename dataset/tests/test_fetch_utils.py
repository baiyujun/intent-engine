import json, pathlib, subprocess
from unittest import mock
from src import fetch_utils

def test_update_manifest_creates_and_merges(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch_utils, "REPORTS", tmp_path)
    fetch_utils.update_manifest("agentdojo", {"source_ref": "abc", "n_samples": 10})
    fetch_utils.update_manifest("gtfobins", {"source_ref": "def", "n_samples": 5})
    m = fetch_utils.read_manifest()
    assert m["agentdojo"]["source_ref"] == "abc"
    assert m["gtfobins"]["n_samples"] == 5

def test_append_fetch_error_writes_log(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch_utils, "REPORTS", tmp_path)
    fetch_utils.append_fetch_error("bipia", RuntimeError("rate limited"))
    log = (tmp_path / "fetch_errors.log").read_text()
    assert "bipia" in log and "rate limited" in log

def test_clone_or_pull_uses_git(monkeypatch, tmp_path):
    calls = {}
    def fake_run(cmd, **kw):
        calls["cmd"] = cmd
        class R: returncode = 0; stdout = ""
        return R()
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(fetch_utils, "_head_sha", lambda d: "deadbeef")
    r = fetch_utils.clone_or_pull("https://github.com/x/y", tmp_path / "y")
    assert r["source_ref"] == "deadbeef"
    assert "clone" in calls["cmd"][1] or "pull" in " ".join(calls["cmd"])
