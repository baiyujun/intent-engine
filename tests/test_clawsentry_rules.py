import pathlib
from src import normalize_utils
from scripts import normalize_clawsentry_rules
from src.schema import validate_record
import re

def test_clawsentry_rule_derived(monkeypatch, tmp_path):
    monkeypatch.setattr(normalize_clawsentry_rules, "RAW_DIR", pathlib.Path("tests/fixtures/clawsentry_rules"))
    monkeypatch.setattr(normalize_utils, "ROOT", tmp_path, raising=False)
    normalize_clawsentry_rules.main()
    recs = normalize_utils.read_slice("clawsentry_rules")
    assert recs
    assert all(r["license_status"] == "ok" for r in recs)
    assert all(r["label"]["confidence"] == "medium" for r in recs)
    # each generated sample must hit at least one rule pattern
    assert all("rule_derived" in (r["notes"] or "") for r in recs)
    assert all(validate_record(r) == [] for r in recs)
