"""Shared normalize helpers: per-source slice I/O, JSONL streaming.

All paths derive from the live module-level ROOT via accessor functions, so
tests can redirect the whole tree with monkeypatch.setattr(normalize_utils,
"ROOT", tmp_path) — no path constants are bound at import time."""
import json, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]

def processed_dir() -> pathlib.Path:
    return ROOT / "processed"

def per_source_dir() -> pathlib.Path:
    return processed_dir() / "per_source"

def reports_dir() -> pathlib.Path:
    return ROOT / "reports"

def slice_path(source_key: str) -> pathlib.Path:
    return per_source_dir() / f"{source_key}.jsonl"

def make_turn(role: str, text: str, origin: str, idx: int = 0) -> dict:
    return {"turn_index": idx, "role": role, "raw_text": text, "instruction_origin": origin}

def write_jsonl(path: pathlib.Path, records) -> None:
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def iter_jsonl(path: pathlib.Path):
    with pathlib.Path(path).open() as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

def write_slice(source_key: str, records) -> pathlib.Path:
    p = slice_path(source_key)
    write_jsonl(p, records)
    return p

def read_slice(source_key: str) -> list:
    p = slice_path(source_key)
    return list(iter_jsonl(p)) if p.exists() else []
