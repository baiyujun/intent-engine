"""Normalize 3 HF prompt-injection datasets -> one slice.

Real data is saved by `fetch_hf_injections` via `datasets.save_to_disk` ->
`raw/hf_injections/<src_key>/dataset_dict.json` + parquet splits (HF
`DatasetDict` format). We load via `datasets.load_from_disk` and iterate ALL
splits (train/test/validation). A CSV fixture fallback
(`tests/fixtures/hf/<fname>.csv`) is kept so the offline test still runs against
committed fixtures when the real `raw/` data is absent.

deepset=ok/Apache, jayavibhav+imoxto=needs_confirmation/none (gate-driven).
"""
import csv, pathlib
from src.schema import make_record, validate_record
from src.normalize_utils import write_slice, make_turn
from src.licenses import license_status, license_spdx

RAW_DIR = pathlib.Path("raw/hf_injections")

# (src_key, csv_fixture_name, text_col, label_col)
# text_col / label_col are the REAL HF dataset column names (confirmed via
# load_from_disk inspection) AND match the CSV fixture headers (so one code
# path serves both real and fixture data).
SPECS = [
    ("hf_deepset", "deepset.csv", "text", "label"),
    ("hf_jayavibhav", "jayavibhav.csv", "text", "label"),
    ("hf_imoxto", "imoxto.csv", "text", "labels"),
]

def _truthy(v):
    """Map a binary label value to bool. HF labels are 0/1 ints; tolerate
    strings ('1','true','yes','injection') for fixture/external compatibility."""
    return str(v).strip() in ("1", "true", "True", "yes", "injection")

def _emit(src_key, text, mal, i, recs):
    recs.append(make_record(
        _raw_id=f"{src_key}_{i}", source_dataset=src_key,
        license=license_spdx(src_key), license_status=license_status(src_key),
        modality="single_turn",
        turns=[make_turn("user", text, "user_direct")],
        structured_action={"action_type": "unknown", "target_resource": None, "stated_purpose": None},
        label={"risk_category": "prompt_injection" if mal else "benign",
               "is_malicious": mal, "attack_family": "direct_injection" if mal else "benign",
               "purpose_capability_consistent": True, "confidence": "high",
               "attack_stage_precursor": False},
        notes=f"{src_key} binary label"))

def _load_real(src_key, text_col, lab_col, recs):
    """Load real HF save_to_disk data via load_from_disk; iterate all splits."""
    from datasets import load_from_disk
    dd = load_from_disk(str(RAW_DIR / src_key))
    i = 0
    for split_name in dd.keys():
        split = dd[split_name]
        for row in split:
            text = (row.get(text_col) or "")
            if not (text and str(text).strip()):
                i += 1
                continue
            mal = _truthy(row.get(lab_col))
            _emit(src_key, str(text), mal, i, recs)
            i += 1

def main():
    recs = []
    for src_key, fname, text_col, lab_col in SPECS:
        real_path = RAW_DIR / src_key / "dataset_dict.json"
        if real_path.exists():
            try:
                _load_real(src_key, text_col, lab_col, recs)
            except Exception as e:
                print(f"[hf_injections] WARN: load_from_disk failed for {src_key}: {e}; skipping")
            continue
        # CSV fallback: real raw dir (stray CSVs) OR monkeypatched fixture dir.
        f = RAW_DIR / fname
        if f.exists():
            with f.open() as fh:
                for i, row in enumerate(csv.DictReader(fh)):
                    text = row.get(text_col) or ""
                    if not text.strip():
                        continue
                    mal = _truthy(row.get(lab_col))
                    _emit(src_key, text, mal, i, recs)
    recs = [r for r in recs if validate_record(r) == []]
    return write_slice("hf_injections", recs)

if __name__ == "__main__": main()
