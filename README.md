# Vulnity - AI Vulnerability Orchestrator
 
<p align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker)
![Ollama](https://img.shields.io/badge/Ollama-LLM-black?style=flat-square)
![FAISS](https://img.shields.io/badge/FAISS-RAG-009688?style=flat-square)

</p>

AI Vulnerability Orchestrator is a security analysis framework that aggregates findings from multiple security scanners, normalizes and prioritizes vulnerabilities using threat intelligence, and generates AI-assisted remediation with Retrieval-Augmented Generation (RAG) and an independent LLM verification step.

## Features

- Multi-tool vulnerability aggregation (SAST, DAST, SCA)
- Finding normalization and deduplication
- Threat-intelligence-based prioritization (CVSS, EPSS, KEV)
- RAG-assisted remediation generation
- Independent Generator → Judge verification
- Modular scanner integrations

## Architecture

```text
Security Scanners
        │
        ▼
Normalization
        │
        ▼
Deduplication
        │
        ▼
Priority Scoring
        │
        ▼
RAG Retrieval
        │
        ▼
LLM Generator
        │
        ▼
LLM Judge
        │
        ▼
Verified Remediation
```

## Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

Build the RAG knowledge base:

```bash
python rag_build.py
```
```bash
docker compose up --build
```

Run tests:

```bash
pytest
```

