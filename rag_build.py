# rag_build.py — one-time (re-runnable) offline build script for the RAG index.
#
# Mirrors build_lookups.py: run manually whenever knowledge/ changes,
# not part of the live scan pipeline. Produces rag_store/index.faiss +
# rag_store/meta.json, which rag.py loads at runtime.
#
# Usage:
#   python rag_build.py
#   python rag_build.py --knowledge-dir knowledge --out-dir rag_store

import argparse
import json
import os
import re
import sys

import numpy as np
import faiss

from rag import embed_text, EMBED_MODEL, OLLAMA_BASE_URL


def chunk_markdown(path: str) -> list[dict]:
    """
    Split a markdown file into chunks along its '## ' section headers.
    This is structure-aware rather than a fixed-size window, because the
    knowledge docs are already organized into short, self-contained
    sections (Description / Remediation / Verification, etc.) that make
    good retrieval units on their own.
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    title_match = re.match(r"^#\s+(.+)$", text, re.MULTILINE)
    doc_title = title_match.group(1).strip() if title_match else os.path.basename(path)

    # Split on '## ' section headers, keeping the header with its body.
    sections = re.split(r"(?=^## )", text, flags=re.MULTILINE)

    chunks = []
    for section in sections:
        section = section.strip()
        if not section or section.startswith("# "):
            # Skip the bare top-level title-only fragment before the first '## '
            if section.startswith("# ") and "## " not in section:
                continue
        if not section:
            continue
        # Prefix every chunk with the document title so retrieval + the
        # prompt shown to the LLM carries the vulnerability class context
        # even for short sections like "## Verification".
        chunk_text = f"# {doc_title}\n\n{section}" if not section.startswith("# ") else section
        chunks.append({
            "text": chunk_text.strip(),
            "source": os.path.basename(path),
        })
    return chunks


def build_index(knowledge_dir: str, out_dir: str) -> None:
    if not os.path.isdir(knowledge_dir):
        print(f"[rag_build] ERROR: knowledge dir not found: {knowledge_dir}")
        sys.exit(1)

    md_files = sorted(
        os.path.join(knowledge_dir, f)
        for f in os.listdir(knowledge_dir)
        if f.endswith(".md")
    )
    if not md_files:
        print(f"[rag_build] ERROR: no .md files found in {knowledge_dir}")
        sys.exit(1)

    print(f"[rag_build] Found {len(md_files)} knowledge documents in {knowledge_dir}")

    all_chunks: list[dict] = []
    for path in md_files:
        file_chunks = chunk_markdown(path)
        all_chunks.extend(file_chunks)
        print(f"[rag_build]   {os.path.basename(path)}: {len(file_chunks)} chunks")

    print(f"[rag_build] {len(all_chunks)} total chunks. Embedding via "
          f"'{EMBED_MODEL}' at {OLLAMA_BASE_URL} ...")

    vectors = []
    kept_chunks = []
    for i, chunk in enumerate(all_chunks):
        vec = embed_text(chunk["text"])
        if vec is None:
            print(f"[rag_build] WARNING: failed to embed chunk {i} "
                  f"from {chunk['source']} — skipping.")
            continue
        vectors.append(vec)
        kept_chunks.append(chunk)
        if (i + 1) % 10 == 0 or (i + 1) == len(all_chunks):
            print(f"[rag_build]   embedded {i + 1}/{len(all_chunks)}")

    if not vectors:
        print("[rag_build] ERROR: no chunks were successfully embedded. "
              "Is Ollama running with the embedding model pulled? "
              f"(`ollama pull {EMBED_MODEL}`)")
        sys.exit(1)

    matrix = np.array(vectors, dtype="float32")
    faiss.normalize_L2(matrix)  # so inner product == cosine similarity

    dim = matrix.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(matrix)

    os.makedirs(out_dir, exist_ok=True)
    index_path = os.path.join(out_dir, "index.faiss")
    meta_path = os.path.join(out_dir, "meta.json")

    faiss.write_index(index, index_path)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(kept_chunks, f, indent=2)

    print(f"[rag_build] Wrote {index.ntotal} vectors (dim={dim}) to {index_path}")
    print(f"[rag_build] Wrote chunk metadata to {meta_path}")
    print("[rag_build] Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the FAISS RAG index from knowledge/.")
    parser.add_argument("--knowledge-dir", default="knowledge",
                        help="Directory of .md reference docs (default: knowledge)")
    parser.add_argument("--out-dir", default="rag_store",
                        help="Output directory for the FAISS index + metadata (default: rag_store)")
    args = parser.parse_args()

    build_index(args.knowledge_dir, args.out_dir)
