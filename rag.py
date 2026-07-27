# rag.py — runtime retrieval interface for RAG-augmented patch generation.
#
# This module ONLY reads an index that must already exist on disk
# (built once, offline, by rag_build.py — same pattern as build_lookups.py
# producing lookups.pkl). It does no embedding-model calls at import time
# and degrades gracefully (returns []) if the index is missing or Ollama
# is unreachable, so it never breaks the scan pipeline.

import os
import json
from functools import lru_cache

import numpy as np
import requests

try:
    import faiss
except ImportError:  # pragma: no cover - faiss should always be installed
    faiss = None

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
EMBED_MODEL     = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
EMBED_URL       = f"{OLLAMA_BASE_URL}/api/embeddings"
EMBED_TIMEOUT   = int(os.getenv("OLLAMA_EMBED_TIMEOUT", "30"))

RAG_STORE_DIR   = os.getenv("RAG_STORE_PATH", "rag_store")
INDEX_PATH      = os.path.join(RAG_STORE_DIR, "index.faiss")
META_PATH       = os.path.join(RAG_STORE_DIR, "meta.json")


# ---------------------------------------------------------------------------
# Embedding
# ---------------------------------------------------------------------------

def embed_text(text: str) -> list[float] | None:
    """
    Get an embedding vector for a piece of text from Ollama.
    Returns None (never raises) if the embedding model/service is
    unavailable, so callers can fail open rather than crash the pipeline.
    """
    try:
        r = requests.post(
            EMBED_URL,
            json={"model": EMBED_MODEL, "prompt": text},
            timeout=EMBED_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        vec = data.get("embedding")
        if not vec:
            print(f"[rag] WARNING: empty embedding returned for query.")
            return None
        return vec
    except requests.exceptions.ConnectionError:
        print(f"[rag] WARNING: could not connect to Ollama embeddings at {EMBED_URL}")
        return None
    except requests.exceptions.Timeout:
        print(f"[rag] WARNING: embedding request timed out after {EMBED_TIMEOUT}s")
        return None
    except Exception as e:
        print(f"[rag] WARNING: embedding failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Index loading (cached — the index is read-only at runtime)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_index():
    """
    Load the FAISS index + chunk metadata built by rag_build.py.
    Returns (index, chunks) or (None, None) if not present/loadable.
    Cached in memory after first successful load.
    """
    if faiss is None:
        print("[rag] WARNING: faiss is not installed — retrieval disabled.")
        return None, None

    if not (os.path.exists(INDEX_PATH) and os.path.exists(META_PATH)):
        print(f"[rag] No index found at {RAG_STORE_DIR} — "
              f"run `python rag_build.py` to build it. Retrieval disabled.")
        return None, None

    try:
        index = faiss.read_index(INDEX_PATH)
        with open(META_PATH, "r", encoding="utf-8") as f:
            chunks = json.load(f)
        return index, chunks
    except Exception as e:
        print(f"[rag] WARNING: failed to load index: {e}")
        return None, None


# ---------------------------------------------------------------------------
# Query building
# ---------------------------------------------------------------------------

def _build_query(issue: dict) -> str:
    """
    Build a short retrieval query from a normalized finding dict.
    Uses the same fields cvc.py already stamps on every finding
    (category, cwe, name) so this needs no schema changes upstream.
    """
    parts = []
    if issue.get("category"):
        parts.append(issue["category"])
    if issue.get("cwe"):
        parts.append(issue["cwe"])
    if issue.get("name"):
        parts.append(issue["name"])
    if issue.get("description"):
        parts.append(issue["description"][:300])
    return " — ".join(parts) if parts else "web application vulnerability"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def retrieve_context(issue: dict, k: int = 3) -> list[dict]:
    """
    Retrieve the top-k most relevant reference chunks for a finding.

    Returns a list of {"text": str, "source": str} dicts, most relevant
    first. Returns [] if the index isn't built or embeddings/index are
    unavailable — callers should treat that as "no extra context", not
    an error.
    """
    index, chunks = _load_index()
    if index is None or not chunks:
        return []

    query = _build_query(issue)
    query_vec = embed_text(query)
    if query_vec is None:
        return []

    query_arr = np.array([query_vec], dtype="float32")
    faiss.normalize_L2(query_arr)

    k = min(k, index.ntotal)
    if k <= 0:
        return []

    scores, ids = index.search(query_arr, k)

    results = []
    for score, idx in zip(scores[0], ids[0]):
        if idx < 0 or idx >= len(chunks):
            continue
        chunk = chunks[idx]
        results.append({
            "text": chunk["text"],
            "source": chunk.get("source", "unknown"),
            "score": float(score),
        })
    return results
