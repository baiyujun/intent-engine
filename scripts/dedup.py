"""Dedup unified.jsonl by embedding similarity (fallback TF-IDF). Within-family + benign-global."""
import json, pathlib, os
import numpy as np
from src.schema import canonical_text
from src.normalize_utils import iter_jsonl, write_jsonl, processed_dir, reports_dir
THRESH = float(os.environ.get("DEDUP_THRESHOLD", "0.92"))
MODEL = os.environ.get("DEDUP_EMBED_MODEL", "paraphrase-multilingual-MiniLM-L12-v2")
CONF_RANK = {"high": 3, "medium": 2, "low": 1}

def _embed(texts):
    try:
        from sentence_transformers import SentenceTransformer
        m = SentenceTransformer(MODEL)
        return np.asarray(m.encode(texts, normalize_embeddings=True)), "embedding"
    except Exception:
        from sklearn.feature_extraction.text import TfidfVectorizer
        v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5), min_df=1)
        X = v.fit_transform(texts).toarray()
        norms = np.linalg.norm(X, axis=1, keepdims=True); norms[norms == 0] = 1
        return (X / norms), "tfidf"

def _key(r): return r["label"]["attack_family"] if r["label"]["is_malicious"] else "benign_global"

def _cluster_keep(records):
    if len(records) <= 1: return records, 0, None
    embs, method = _embed([canonical_text(r) for r in records])
    sim = embs @ embs.T
    keep, removed = [], 0
    for i, r in enumerate(records):
        if any(sim[i][j] >= THRESH for j in keep):
            # near-dup; keep representative with higher confidence then lower id
            for k in keep:
                if sim[i][k] >= THRESH:
                    kc = CONF_RANK.get(records[k]["label"]["confidence"], 0)
                    ic = CONF_RANK.get(r["label"]["confidence"], 0)
                    if ic > kc or (ic == kc and r["id"] < records[k]["id"]):
                        keep[keep.index(k)] = i
                    removed += 1
                    break
        else:
            keep.append(i)
    return [records[i] for i in keep], removed, method

def main():
    src = processed_dir() / "unified.jsonl"
    records = list(iter_jsonl(src))
    by_fam = {}
    for r in records: by_fam.setdefault(_key(r), []).append(r)
    kept, removed_total, method = [], 0, None
    per_family = {}
    for fam, recs in by_fam.items():
        k, rm, m = _cluster_keep(recs)
        kept.extend(k); per_family[fam] = {"kept": len(k), "removed": rm}
        removed_total += rm
        if m and not method: method = m
    method = method or "tfidf"
    kept.sort(key=lambda r: r["id"])
    out = processed_dir() / "unified_dedup.jsonl"
    write_jsonl(out, kept)
    rep = reports_dir(); rep.mkdir(parents=True, exist_ok=True)
    per_source = {}
    for r in kept: per_source[r["source_dataset"]] = per_source.get(r["source_dataset"], 0) + 1
    (rep / "dedup_report.json").write_text(json.dumps({
        "method": method, "threshold": THRESH, "model": MODEL,
        "input": len(records), "kept": len(kept), "removed": removed_total,
        "per_family": per_family, "per_source_kept": per_source}, indent=2))
    return out
if __name__ == "__main__": main()
