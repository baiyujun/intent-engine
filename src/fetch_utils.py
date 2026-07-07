"""Shared fetch helpers: git clone/pull, file download, manifest, error log."""
import json, pathlib, subprocess, datetime, requests

ROOT = pathlib.Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
REPORTS = ROOT / "reports"

def _now_iso() -> str:
    # fixed-ish timestamp from system clock; ok for manifest (not for workflow scheduling)
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _head_sha(repo_dir: pathlib.Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:
        return "unknown"

def clone_or_pull(url: str, dest: pathlib.Path, depth: int = 1) -> dict:
    dest = pathlib.Path(dest)
    if dest.exists() and (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "pull", "--depth", str(depth), "--ff-only"],
                       check=False, capture_output=True)
        action = "pull"
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", str(depth), url, str(dest)],
                       check=True, capture_output=True)
        action = "clone"
    return {"source_ref": _head_sha(dest), "fetched_at": _now_iso(), "action": action}

def download_file(url: str, dest: pathlib.Path, timeout: int = 60) -> dict:
    dest = pathlib.Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    dest.write_bytes(r.content)
    return {"source_ref": url, "fetched_at": _now_iso(), "action": "download", "bytes": len(r.content)}

def read_manifest() -> dict:
    p = REPORTS / "fetch_manifest.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())

def update_manifest(source_key: str, entry: dict) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    m = read_manifest()
    m[source_key] = entry
    (REPORTS / "fetch_manifest.json").write_text(json.dumps(m, indent=2, ensure_ascii=False))

def append_fetch_error(source_key: str, exc: Exception) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    with (REPORTS / "fetch_errors.log").open("a") as f:
        f.write(f"[{_now_iso()}] {source_key}: {type(exc).__name__}: {exc}\n")
