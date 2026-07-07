"""Merge all per_source slices -> processed/unified.jsonl (overwrite)."""
import json, pathlib
from src.normalize_utils import iter_jsonl, per_source_dir, processed_dir, reports_dir

def main():
    pd = processed_dir(); pd.mkdir(parents=True, exist_ok=True)
    out = pd / "unified.jsonl"
    counts = {}
    with out.open("w") as f:
        for p in sorted(per_source_dir().glob("*.jsonl")):
            src = p.stem
            n = 0
            for r in iter_jsonl(p):
                f.write(json.dumps(r, ensure_ascii=False) + "\n"); n += 1
            counts[src] = n
    rep = reports_dir(); rep.mkdir(parents=True, exist_ok=True)
    (rep / "unified_count.json").write_text(json.dumps(counts, indent=2))
    return out
if __name__ == "__main__": main()
