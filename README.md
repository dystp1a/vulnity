# AI Vulnerability Orchestrator

Containerized security orchestration stack that combines:
- **SAST** (SonarQube)
- **DAST** (OWASP ZAP)
- **SCA** (Trivy)
- **Targeted pentest checks** (Nuclei, SQLMap, Metasploit helpers)
- **AI remediation suggestions** via **Ollama** (default model: `deepseek-coder:6.7b`)
- **Dashboard UI** in Streamlit

The app runs a full scan pipeline, normalizes findings, ranks risk using custom scoring (`cvc.py`), and generates patch guidance for top findings.

---

## Prerequisites

Install these first:
- Docker Engine
- Docker Compose plugin (`docker compose`)
- Git

Recommended host resources:
- 16 GB RAM minimum 
- Linux/WSL2 

---

## Quick Setup

```bash
git clone https://github.com/L11cif3r/AI-Vulnerability-Orchestrator.git
cd AI-Vulnerability-Orchestrator
```

### 1) Create environment file

Create a `.env` file in the repo root:

```bash
cat > .env << 'EOF'
SONAR_TOKEN=replace_with_your_sonarqube_token
EOF
```

### 2) Start core services

```bash
docker compose up -d --build
```

### 3) Pull the Ollama model used by the app

```bash
docker compose exec ollama ollama pull deepseek-coder:6.7b
```

> You can use another model by setting `OLLAMA_MODEL` (for example in `docker-compose.yml` or environment) as long as it exists in Ollama.

### 4) Initialize SonarQube and create token

1. Open `http://localhost:9000`
2. Login with default credentials: `admin` / `admin`
3. Change password when prompted
4. Generate a user token
5. Put that token into `.env` as `SONAR_TOKEN=...`
6. Restart the orchestrator service so it picks up the token:

```bash
docker compose up -d orchestrator
```

### 5) Open the dashboard

Go to: `http://localhost:8501`

Use sidebar defaults (or your own target URL + repo URL), then click **Start Full Scan**.

---

## Commands You Will Use Most

### Start everything
```bash
docker compose up -d --build
```

### Check running containers
```bash
docker compose ps
```

### Follow orchestrator logs
```bash
docker compose logs -f orchestrator
```

### Stop everything
```bash
docker compose down
```

### Stop and delete volumes (fresh reset)
```bash
docker compose down -v
```

---

## Build `lookups.pkl` from Kaggle dataset

`lookups.pkl` is required by the ranking engine. If missing, generate it from `kaggle.csv`.

1. Download `kaggle.csv` from:
   [Kaggle Vulnerability Management Datasets](https://www.kaggle.com/datasets/francescomanzoni/vulnerability-management-datasets?resource=download)
2. Place `kaggle.csv` in the repo root (same folder as `cvc.py`).
3. Build lookups:

```bash
python build_lookups.py kaggle.csv
```

---

## Service Endpoints

- Streamlit dashboard: `http://localhost:8501`
- SonarQube: `http://localhost:9000`
- OWASP ZAP API: `http://localhost:8080`
- Juice Shop target app: `http://localhost:3000`
- Ollama API: `http://localhost:11434`

---


## Troubleshooting

- **SonarQube not ready / scan fails**
  - wait longer on first boot; SonarQube initialization can take several minutes
  - verify token is set in `.env` and restart `orchestrator`

- **LLM patch generation unavailable**
  - ensure Ollama is up: `docker compose ps`
  - ensure model exists: `docker compose exec ollama ollama list`
  - pull missing model: `docker compose exec ollama ollama pull deepseek-coder:6.7b`

- **ZAP or Juice Shop unstable under low memory**
  - allocate more RAM to Docker/WSL2
  - restart stack: `docker compose down && docker compose up -d --build`

---

## Security Notice

Use only in authorized environments and for legal security testing/education.
