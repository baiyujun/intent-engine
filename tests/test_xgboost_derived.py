"""Tests for the XGBoost-paper-derived synthetic data generator."""
import json
import re

import pytest

from synth import xgboost_derived as mod
from synth.xgboost_derived import (
    SRC_KEY, OUTPUT,
    gen_split_exfil, gen_benign_split_exfil,
    gen_context_laundering, gen_benign_context_laundering,
    gen_privilege_drift, gen_benign_privilege_drift,
    gen_staged_burst, gen_benign_staged_burst,
    main,
)
from schema import validate_record, canonical_text


SEND_VERBS = re.compile(r"\b(send|email|upload|post|forward|pipe)\b", re.IGNORECASE)
READ_VERBS = re.compile(r"\b(read|cat|see|display|open|dump)\b", re.IGNORECASE)
EXFIL_VERBS = re.compile(r"\b(send|email|upload|post|forward|pipe)\b", re.IGNORECASE)


def _texts(r):
    return [t["raw_text"] for t in r["turns"]]


# ── per-family structure tests ───────────────────────────────────────────────

def test_split_exfil_structure():
    r = gen_split_exfil(0)
    assert len(r["turns"]) == 2
    assert r["label"]["is_malicious"] is True
    assert r["label"]["attack_family"] == "split_exfil"
    assert r["label"]["risk_category"] == "exfiltration"
    assert r["label"]["purpose_capability_consistent"] is False
    texts = _texts(r)
    assert READ_VERBS.search(texts[0]), texts[0]
    assert SEND_VERBS.search(texts[1]), texts[1]
    assert validate_record(r) == []


def test_context_laundering_structure():
    r = gen_context_laundering(0)
    assert len(r["turns"]) == 4
    assert r["label"]["is_malicious"] is True
    assert r["label"]["attack_family"] == "context_laundering"
    last = _texts(r)[-1]
    assert SEND_VERBS.search(last), last
    assert validate_record(r) == []


def test_privilege_drift_structure():
    r = gen_privilege_drift(0)
    assert len(r["turns"]) == 4
    assert r["label"]["is_malicious"] is True
    assert r["label"]["attack_family"] == "privilege_drift"
    assert r["label"]["risk_category"] == "privilege_escalation"
    for t in _texts(r):
        assert not EXFIL_VERBS.search(t), f"exfil verb found in privilege_drift turn: {t}"
    assert validate_record(r) == []


def test_staged_burst_structure():
    r = gen_staged_burst(0)
    assert len(r["turns"]) == 3
    assert r["label"]["is_malicious"] is True
    assert r["label"]["attack_family"] == "staged_burst"
    texts = _texts(r)
    assert READ_VERBS.search(texts[0]), texts[0]
    assert READ_VERBS.search(texts[1]), texts[1]
    assert SEND_VERBS.search(texts[2]), texts[2]
    # the two sensitive files must differ
    assert texts[0] != texts[1]
    assert validate_record(r) == []


# ── benign controls ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("gen", [
    gen_benign_split_exfil,
    gen_benign_context_laundering,
    gen_benign_privilege_drift,
    gen_benign_staged_burst,
])
def test_benign_controls(gen):
    r = gen(0)
    assert r["label"]["is_malicious"] is False
    assert r["label"]["attack_family"] == "benign"
    assert r["label"]["purpose_capability_consistent"] is True
    assert r["label"]["risk_category"] == "benign"
    # no send-to-external verb anywhere
    for t in _texts(r):
        assert not EXFIL_VERBS.search(t), f"exfil verb in benign turn: {t}"
    assert validate_record(r) == []


# ── end-to-end validate-all + count tests (monkeypatch OUTPUT) ─────────────────

def test_validates_all(tmp_path, monkeypatch):
    out = tmp_path / "x.jsonl"
    monkeypatch.setattr(mod, "OUTPUT", str(out))
    monkeypatch.setenv("N_PER_FAMILY", "20")
    main()
    assert out.exists()
    recs = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    assert len(recs) == 20 * 8
    for r in recs:
        assert validate_record(r) == []


def test_id_deterministic():
    a = gen_split_exfil(7)
    b = gen_split_exfil(7)
    assert a["id"] == b["id"]
    c = gen_split_exfil(8)
    assert a["id"] != c["id"]


def test_ids_unique_and_text_distinct():
    records = [gen_split_exfil(i) for i in range(50)]
    ids = [r["id"] for r in records]
    texts = [canonical_text(r) for r in records]
    assert len(set(ids)) == len(ids)
    assert len(set(texts)) == len(texts)


def test_count(tmp_path, monkeypatch):
    out = tmp_path / "x.jsonl"
    monkeypatch.setattr(mod, "OUTPUT", str(out))
    monkeypatch.setenv("N_PER_FAMILY", "5")
    main()
    assert out.exists()
    recs = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
    assert len(recs) == 4 * 5 * 2
    # 8 (family,kind) groups each of size 5. Benign records all share
    # attack_family "benign" (per spec), so we discriminate the 4 benign
    # families by matching the known family name embedded in the record id.
    from collections import Counter
    FAMILIES = ["split_exfil", "context_laundering", "privilege_drift", "staged_burst"]
    groups = Counter()
    for r in recs:
        rid = r["id"]
        family = next(f for f in FAMILIES if f in rid)
        kind = "attack" if r["label"]["is_malicious"] else "benign"
        groups[f"{family}_{kind}"] += 1
    assert len(groups) == 8
    assert all(v == 5 for v in groups.values())
