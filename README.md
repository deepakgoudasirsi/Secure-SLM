# Secure-SLM

[![CI](https://github.com/deepakgoudasirsi/Secure-SLM/actions/workflows/ci.yml/badge.svg)](https://github.com/deepakgoudasirsi/Secure-SLM/actions/workflows/ci.yml)

**Lightweight Secure Small Language Model for Network Threat Detection and Security Log Analysis**

Secure-SLM ingests security logs, detects threats with **rules + ML**, enriches analysis with **MITRE ATT&CK RAG**, and generates incident reports using a **local SLM pipeline** (no cloud required).

## Features

- Log preprocessing (Windows, syslog, firewall, IDS, auth)
- Rule-based + ML threat detection (brute force, port scan, malware, priv esc, DDoS)
- MITRE ATT&CK knowledge retrieval
- Local SLM explanations (template mode; optional Hugging Face)
- Prompt-injection filtering · JWT auth · SQLite · Web dashboard · Docker · CI

## Quick Start

```bash
git clone https://github.com/deepakgoudasirsi/Secure-SLM.git
cd Secure-SLM
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
./run.sh
```

| Resource | URL |
|----------|-----|
| Dashboard | http://localhost:8000/ |
| API docs | http://localhost:8000/docs |
| Login | `admin` / `changeme` |

## Example

**Input:** `Failed login attempt from IP 192.168.1.20 repeated 45 times. User: admin`

**Output:** Brute Force Attack · High severity · MITRE context · mitigation steps

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | JWT token |
| POST | `/api/v1/analysis/analyze` | Full pipeline |
| GET | `/api/v1/alerts` | List alerts |
| POST | `/api/v1/evaluation/run` | Accuracy benchmark |

## Development

```bash
pytest -q
python scripts/evaluate.py
python scripts/seed_sample_logs.py
docker compose up --build
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SLM_MODE` | `template` | `template` or `huggingface` |
| `ENABLE_ML_CLASSIFIER` | `true` | TF-IDF threat classifier |
| `ENABLE_MITRE_RAG` | `true` | MITRE ATT&CK enrichment |

## License

MIT — see [LICENSE](LICENSE).
