"""Shared pytest config for the intent-engine repo.

Two things, both overridable by an explicit environment value:

1. Importability. The generator and Tier 0 reuse the dataset's
   ``schema`` / ``normalize_utils`` / ``licenses`` modules (flat imports,
   matching ``tier0/vector_index.py``'s ``from schema import canonical_text``).
   We insert the dataset ``src`` dir and this repo root onto ``sys.path`` so a
   bare ``pytest`` resolves them without relying on a hand-set ``PYTHONPATH``.
   The dataset now lives in-repo under ``dataset/`` (merged from the former
   standalone dataset repo), so the path is relative to this repo root.

2. Test backend. Tier 0's vector path has a fast deterministic sklearn backend
   (``TIER0_FORCE_SKLEARN=1``) and a slow real FAISS+MiniLM backend. Tests
   default to sklearn so the suite is fast and hermetic; set
   ``TIER0_FORCE_SKLEARN=0`` (or unset, with an explicit override) to exercise
   the real backend. ``setdefault`` respects an explicit env value.
"""
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
DATASET_ROOT = REPO_ROOT / "dataset"
DATASET_SRC = DATASET_ROOT / "src"

for _p in (str(REPO_ROOT), str(DATASET_SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("TIER0_FORCE_SKLEARN", "1")
