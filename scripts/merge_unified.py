"""Merge all per_source slices -> processed/unified.jsonl (overwrite).

v0 tractability: each source is capped to MAX_PER_SOURCE records (env, default
5000; 0 = no cap) so dedup's O(n^2) per-family clustering stays in memory. The
ok-license training sources are all < 5000, so the cap only samples the huge
needs_confirmation sets (held out of training) for statistics. A full run with
no cap requires a non-O(n^2) dedup (future work)."""
import json, os, pathlib
from src.normalize_utils import iter_jsonl, per_source_dir, processed_dir, reports_dir

MAX_PER_SOURCE = int(os.environ.get("MAX_PER_SOURCE", "5000"))

def main():
    pd = processed_dir(); pd.mkdir(parents=True, exist_ok=True)
    out = pd / "unified.jsonl"
    counts = {}
    with out.open("w") as f:
        for p in sorted(per_source_dir().glob("*.jsonl")):
            src = p.stem
            n = 0
            for r in iter_jsonl(p):
                if MAX_PER_SOURCE and n >= MAX_PER_SOURCE:
                    break
                f.write(json.dumps(r, ensure_ascii=False) + "\n"); n += 1
            counts[src] = n
    rep = reports_dir(); rep.mkdir(parents=True, exist_ok=True)
    (rep / "unified_count.json").write_text(json.dumps(counts, indent=2))
    return out
if __name__ == "__main__": main()
