"""Tier 0 vector index — dual-cluster FAISS nearest-neighbor index.

Builds TWO FAISS ``IndexFlatL2`` indices (one for benign, one for malicious
records) from the dataset's train split. For each record the canonical text is
obtained via :func:`schema.canonical_text` (turns[].raw_text joined with the
structured_action target_resource / stated_purpose). New inputs are embedded
and searched against each cluster for the single nearest neighbor:

    d_benign     = L2 distance to nearest benign neighbor
    d_malicious  = L2 distance to nearest malicious neighbor
    margin       = d_malicious - d_benign

Positive margin → input is *closer* to a benign neighbor (smaller benign
distance) → more likely benign. Negative margin → closer to malicious.

Indices + metadata (ids) are persisted under ``save_dir`` as ``.faiss`` +
``.json`` files so queries can reload them without re-embedding the training
set. The sentence-transformers model is cached by the library under
``~/.cache/torch/sentence_transformers/``.

Fallback: if ``sentence-transformers`` cannot be imported, we degrade to
``sklearn.feature_extraction.text.TfidfVectorizer`` +
``sklearn.neighbors.NearestNeighbors`` with a shared vocabulary (mirroring the
dataset's ``dedup.py`` fallback approach). In this mode ``model_name`` is
ignored and the persisted index uses sklearn artifacts instead of FAISS.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"
_DEFAULT_SAVE_DIR = "tier0/models"

# Module-level model cache so the (~90s) MiniLM load happens once per process,
# not once per build_index()/query() call. None = not-yet-loaded; False = ST
# unavailable, fall back to sklearn.
_ST_MODEL_CACHE: dict = {}


def _force_sklearn() -> bool:
    """Env switch (TIER0_FORCE_SKLEARN=1) to skip the slow MiniLM model.

    Used by the unit tests so they run on the instant sklearn TF-IDF backend
    instead of paying ~90s of model load per test.
    """
    return os.environ.get("TIER0_FORCE_SKLEARN", "").strip() in ("1", "true", "yes")


# -- canonical text -----------------------------------------------------------

def _canonical_text(record: dict) -> str:
    """Return canonical text for a record.

    Prefer :func:`schema.canonical_text` (imported with ``PYTHONPATH`` pointing
    at the dataset ``src``). Fall back to a local replication if the schema
    module is not importable.
    """
    try:
        from schema import canonical_text  # type: ignore
        return canonical_text(record)
    except Exception:
        parts = [t.get("raw_text", "") for t in record.get("turns", [])]
        sa = record.get("structured_action", {})
        if sa.get("target_resource"):
            parts.append(str(sa["target_resource"]))
        if sa.get("stated_purpose"):
            parts.append(str(sa["stated_purpose"]))
        return " \n ".join(p for p in parts if p)


# -- verdict -----------------------------------------------------------------

@dataclass
class VectorVerdict:
    """Verdict from the dual-cluster nearest-neighbor vector index.

    Attributes
    ----------
    d_benign : float
        L2 distance to the nearest benign neighbor.
    d_malicious : float
        L2 distance to the nearest malicious neighbor.
    margin : float
        ``d_malicious - d_benign``. Positive → closer to benign (more likely
        benign); negative → closer to malicious.
    nearest_benign_id : str
        Id of the nearest benign training record ("" if no benign cluster).
    nearest_malicious_id : str
        Id of the nearest malicious training record ("" if no malicious cluster).
    """

    d_benign: float
    d_malicious: float
    margin: float
    nearest_benign_id: str
    nearest_malicious_id: str


# -- embedding backend abstraction -------------------------------------------

def _try_sentence_transformer(model_name: str):
    """Return a sentence-transformers model, or None if unavailable.

    The loaded model is cached per model_name at module level so the slow
    (~90s) load happens once per process. Honors TIER0_FORCE_SKLEARN so tests
    can run on the instant sklearn backend.
    """
    if _force_sklearn():
        return None
    if model_name in _ST_MODEL_CACHE:
        return _ST_MODEL_CACHE[model_name]
    try:
        from sentence_transformers import SentenceTransformer
    except Exception:
        _ST_MODEL_CACHE[model_name] = False
        return None
    try:
        model = SentenceTransformer(model_name)
    except Exception as exc:  # noqa: BLE001 - network/model load failure is recoverable
        logger.warning("sentence-transformers model %s failed to load (%s); falling back to sklearn.", model_name, exc)
        _ST_MODEL_CACHE[model_name] = False
        return None
    _ST_MODEL_CACHE[model_name] = model
    return model


def _st_encode(model, texts: list[str]) -> np.ndarray:
    emb = model.encode(
        texts,
        normalize_embeddings=False,
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    return np.asarray(emb, dtype=np.float32)


# -- index IO helpers --------------------------------------------------------

def _save_dir_path(save_dir: str) -> Path:
    p = Path(save_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


# -- build -------------------------------------------------------------------

def build_index(
    jsonl_path: str,
    model_name: str = _DEFAULT_MODEL,
    save_dir: str = _DEFAULT_SAVE_DIR,
) -> dict:
    """Build dual FAISS L2 indices from a train split and persist them.

    Reads ``jsonl_path`` (one JSON record per line), computes canonical text for
    each record, splits into benign / malicious by ``label.is_malicious``, embeds
    all records, and writes two ``IndexFlatL2`` indices plus per-cluster metadata
    (ids + labels) into ``save_dir``.

    Returns a dict with ``benign_count``, ``malicious_count``, ``model_name``,
    ``save_dir``.
    """
    sdir = _save_dir_path(save_dir)

    records = _read_jsonl(jsonl_path)
    benign_recs: list[dict] = []
    malicious_recs: list[dict] = []
    for rec in records:
        label = rec.get("label", {}) or {}
        if label.get("is_malicious") is True:
            malicious_recs.append(rec)
        else:
            benign_recs.append(rec)

    benign_texts = [_canonical_text(r) for r in benign_recs]
    malicious_texts = [_canonical_text(r) for r in malicious_recs]
    benign_ids = [_record_id(r) for r in benign_recs]
    malicious_ids = [_record_id(r) for r in malicious_recs]

    model = _try_sentence_transformer(model_name)
    if model is not None:
        benign_emb = _st_encode(model, benign_texts) if benign_recs else np.zeros((0, 1), dtype=np.float32)
        malicious_emb = _st_encode(model, malicious_texts) if malicious_recs else np.zeros((0, 1), dtype=np.float32)
        _build_faiss(sdir, benign_emb, malicious_emb, benign_ids, malicious_ids, model_name)
    else:
        logger.warning(
            "sentence-transformers unavailable; falling back to sklearn "
            "TfidfVectorizer + NearestNeighbors (model_name ignored)."
        )
        _build_sklearn(sdir, benign_texts, malicious_texts, benign_ids, malicious_ids)

    return {
        "benign_count": len(benign_recs),
        "malicious_count": len(malicious_recs),
        "model_name": model_name if model is not None else "sklearn-tfidf",
        "save_dir": str(sdir),
    }


def _read_jsonl(path: str) -> list[dict]:
    out: list[dict] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _record_id(rec: dict) -> str:
    rid = rec.get("id")
    if rid is None or str(rid).strip() == "":
        return ""
    return str(rid)


# -- FAISS build/query -------------------------------------------------------

def _build_faiss(
    sdir: Path,
    benign_emb: np.ndarray,
    malicious_emb: np.ndarray,
    benign_ids: list[str],
    malicious_ids: list[str],
    model_name: str,
) -> None:
    import faiss

    benign_index = _make_flat_l2(benign_emb)
    malicious_index = _make_flat_l2(malicious_emb)

    faiss.write_index(benign_index, str(sdir / "benign.faiss"))
    faiss.write_index(malicious_index, str(sdir / "malicious.faiss"))

    meta = {
        "backend": "faiss",
        "index_type": "IndexFlatL2",
        "model_name": model_name,
        "dim": int(benign_emb.shape[1] if benign_emb.size else malicious_emb.shape[1] if malicious_emb.size else 0),
    }
    _write_meta(sdir, "benign", meta, benign_ids)
    _write_meta(sdir, "malicious", meta, malicious_ids)


def _make_flat_l2(emb: np.ndarray):
    import faiss
    if emb.shape[0] == 0:
        return faiss.IndexFlatL2(1)
    dim = int(emb.shape[1])
    index = faiss.IndexFlatL2(dim)
    index.add(np.ascontiguousarray(emb, dtype=np.float32))
    return index


def _write_meta(sdir: Path, cluster: str, meta: dict, ids: list[str]) -> None:
    payload = dict(meta)
    payload["ids"] = ids
    payload["count"] = len(ids)
    with open(sdir / f"{cluster}_meta.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)


def _read_meta(sdir: Path, cluster: str) -> dict:
    with open(sdir / f"{cluster}_meta.json", encoding="utf-8") as f:
        return json.load(f)


# -- sklearn fallback build/query --------------------------------------------

def _build_sklearn(
    sdir: Path,
    benign_texts: list[str],
    malicious_texts: list[str],
    benign_ids: list[str],
    malicious_ids: list[str],
) -> None:
    from sklearn.feature_extraction.text import TfidfVectorizer
    import pickle

    # Shared vocabulary across both clusters (mirrors dedup.py's shared-vectorizer idea)
    all_texts = benign_texts + malicious_texts
    vectorizer = None
    if all_texts:
        vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        vectorizer.fit(all_texts)
        vocab = vectorizer.vocabulary_
        n_features = len(vocab)
    else:
        vocab = {}
        n_features = 0

    # Per-cluster matrices: transform guards the empty cluster (transform([]) raises
    # "0 samples required"), so build an empty matrix by hand for those.
    benign_matrix = _cluster_matrix(vectorizer, benign_texts, n_features)
    malicious_matrix = _cluster_matrix(vectorizer, malicious_texts, n_features)

    from scipy.sparse import save_npz  # type: ignore

    save_npz(str(sdir / "benign_tfidf.npz"), benign_matrix)
    save_npz(str(sdir / "malicious_tfidf.npz"), malicious_matrix)
    # Persist the FITTED vectorizer so query() can transform without re-fitting
    # (a vocabulary-only TfidfVectorizer is not fitted — idf_ is missing).
    with open(sdir / "tfidf_vectorizer.pkl", "wb") as f:
        pickle.dump(vectorizer, f)

    meta = {
        "backend": "sklearn",
        "index_type": "TfidfVectorizer+NearestNeighbors",
        "model_name": "sklearn-tfidf",
        "vocab": vocab,
        "n_features": n_features,
    }
    _write_meta(sdir, "benign", meta, benign_ids)
    _write_meta(sdir, "malicious", meta, malicious_ids)


def _cluster_matrix(vectorizer, texts: list[str], n_features: int):
    """Transform a cluster's texts, returning an empty matrix for the empty cluster."""
    from scipy.sparse import csr_matrix  # type: ignore
    if not texts:
        return csr_matrix((0, max(n_features, 1)), dtype=np.float64)
    return vectorizer.transform(texts)


def _empty_sparse():
    from scipy.sparse import csr_matrix  # type: ignore
    return csr_matrix((0, 0))


def _load_vectorizer(sdir: Path):
    import pickle
    with open(sdir / "tfidf_vectorizer.pkl", "rb") as f:
        return pickle.load(f)


def _sklearn_load_cluster(sdir: Path, cluster: str):
    from scipy.sparse import load_npz  # type: ignore
    matrix = load_npz(str(sdir / f"{cluster}_tfidf.npz"))
    meta = _read_meta(sdir, cluster)
    ids = meta.get("ids", [])
    return matrix, ids


def _sklearn_query(matrix, vectorizer, text: str, ids: list[str]) -> tuple[float, str]:
    from sklearn.neighbors import NearestNeighbors

    if matrix.shape[0] == 0:
        return float("inf"), ""

    q = vectorizer.transform([text])
    if q.shape[1] != matrix.shape[1]:
        return float("inf"), ""

    nn = NearestNeighbors(n_neighbors=1, metric="euclidean", algorithm="brute")
    nn.fit(matrix)
    distances, indices = nn.kneighbors(q)
    d = float(distances[0][0])
    idx = int(indices[0][0])
    nearest_id = ids[idx] if 0 <= idx < len(ids) else ""
    return d, nearest_id


# -- query -------------------------------------------------------------------

def query(
    text: str,
    save_dir: str = _DEFAULT_SAVE_DIR,
    model_name: str = _DEFAULT_MODEL,
) -> VectorVerdict:
    """Query the persisted dual-cluster index for the nearest neighbor in each.

    Reloads the two FAISS (or sklearn) indices from ``save_dir``, embeds
    ``text``, and returns a :class:`VectorVerdict` with the L2 distance to the
    single nearest neighbor in each cluster plus the margin.
    """
    sdir = Path(save_dir)
    meta = _read_meta(sdir, "benign")
    backend = meta.get("backend", "faiss")

    if backend == "sklearn":
        return _query_sklearn(text, sdir)
    return _query_faiss(text, sdir, model_name)


def _query_faiss(text: str, sdir: Path, model_name: str) -> VectorVerdict:
    import faiss

    benign_index = faiss.read_index(str(sdir / "benign.faiss"))
    malicious_index = faiss.read_index(str(sdir / "malicious.faiss"))
    benign_ids = _read_meta(sdir, "benign").get("ids", [])
    malicious_ids = _read_meta(sdir, "malicious").get("ids", [])

    model = _try_sentence_transformer(model_name)
    if model is None:
        # Model went missing between build and query — degrade to sklearn if present.
        logger.warning("sentence-transformers unavailable at query time; falling back to sklearn.")
        return _query_sklearn(text, sdir)

    q = _st_encode(model, [text])

    d_benign, nearest_benign_id = _faiss_search_one(benign_index, q, benign_ids)
    d_malicious, nearest_malicious_id = _faiss_search_one(malicious_index, q, malicious_ids)

    margin = d_malicious - d_benign
    return VectorVerdict(
        d_benign=float(d_benign),
        d_malicious=float(d_malicious),
        margin=float(margin),
        nearest_benign_id=nearest_benign_id,
        nearest_malicious_id=nearest_malicious_id,
    )


def _faiss_search_one(index, q: np.ndarray, ids: list[str]) -> tuple[float, str]:
    n = index.ntotal
    if n == 0:
        return float("inf"), ""
    distances, indices = index.search(np.ascontiguousarray(q, dtype=np.float32), 1)
    d = float(distances[0][0])
    idx = int(indices[0][0])
    nearest_id = ids[idx] if 0 <= idx < len(ids) else ""
    return d, nearest_id


def _query_sklearn(text: str, sdir: Path) -> VectorVerdict:
    vectorizer = _load_vectorizer(sdir)
    benign_matrix, benign_ids = _sklearn_load_cluster(sdir, "benign")
    malicious_matrix, malicious_ids = _sklearn_load_cluster(sdir, "malicious")

    d_benign, nearest_benign_id = _sklearn_query(benign_matrix, vectorizer, text, benign_ids)
    d_malicious, nearest_malicious_id = _sklearn_query(malicious_matrix, vectorizer, text, malicious_ids)

    margin = d_malicious - d_benign
    return VectorVerdict(
        d_benign=float(d_benign),
        d_malicious=float(d_malicious),
        margin=float(margin),
        nearest_benign_id=nearest_benign_id,
        nearest_malicious_id=nearest_malicious_id,
    )
