# SentinelLab

> **Lightweight SOC platform** for threat detection, alert investigation, static file triage, and Markdown incident reports — built as a professional cybersecurity portfolio project.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?style=flat-square&logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Focus-Detection%20Engineering-red?style=flat-square)

---

## Features

- **SOC dashboard** with event metrics, alert queue, investigation view, timeline, and rule catalog
- **SIEM-style detection engine** using external YAML rules
- **Threshold detections** for brute force and internal port scan behavior
- **Endpoint detection** for suspicious PowerShell command lines
- **DNS detection** for potential command-and-control beaconing
- **Static file triage** with SHA256, entropy, extracted strings, suspicious indicators, and risk scoring
- **JSONL log ingestion** through an upload endpoint
- **Markdown incident reports** with executive summary, priority alerts, evidence counts, and next steps
- **Docker Compose support** for reproducible local demos
- **Unit tests** covering detection logic and file analysis

---

## Quick Start

### Requirements

- Python 3.10+
- Docker and Docker Compose, optional but recommended

Confirm Python:

```bash
python --version
```

### Run With Docker

```bash
git clone https://github.com/YOUR_USERNAME/sentinellab.git
cd sentinellab
docker compose up --build
```

Open:

- Frontend: http://localhost:8080
- API docs: http://localhost:8000/docs

### Run Without Docker

```bash
cd SentinelLab/backend
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

On Linux/macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then serve or open the frontend:

```bash
cd ../frontend
python -m http.server 8081
```

Frontend: http://localhost:8081

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | API health check |
| `GET` | `/events` | List normalized security events |
| `GET` | `/rules` | List YAML-backed detection rules |
| `GET` | `/alerts` | Run detections and return alerts |
| `GET` | `/summary` | SOC metrics for the dashboard |
| `POST` | `/ingest` | Upload JSONL logs and run detections |
| `POST` | `/analyze-file` | Upload a file for static triage |
| `POST` | `/reports` | Generate a Markdown incident report |

---

## Running Tests

Install dependencies:

```bash
cd SentinelLab/backend
pip install -r requirements.txt
```

Run the test suite:

```bash
pytest
```

Expected result:

```text
2 passed
```

---

## Project Structure

```text
SentinelLab/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── file_analyzer.py      # SHA256, entropy, strings, risk scoring
│   │   ├── main.py               # FastAPI routes
│   │   ├── models.py             # Pydantic models
│   │   ├── reporting.py          # Markdown report generation
│   │   └── rule_engine.py        # YAML detection engine
│   ├── tests/
│   │   ├── test_detection.py
│   │   └── test_file_analyzer.py
│   ├── pytest.ini
│   └── requirements.txt
├── docs/
│   └── ARCHITECTURE.md           # Architecture and detection flow
├── frontend/
│   ├── index.html                # SOC dashboard
│   ├── styles.css                # Dark professional UI
│   └── app.js                    # API integration and UI state
├── reports/                      # Generated Markdown reports
├── rules/
│   └── detections.yml            # Detection rules
├── samples/
│   ├── files/
│   │   └── suspicious_script.txt # Safe file triage sample
│   └── logs/
│       └── security_events.jsonl # Synthetic security telemetry
├── docker-compose.yml
├── Dockerfile
├── .gitignore
└── README.md
```

---

## Sample Detections

SentinelLab ships with synthetic telemetry that triggers realistic alerts:

| Rule ID | Detection | Severity | Tactic |
|---------|-----------|----------|--------|
| `SL-AUTH-001` | Possible brute force against VPN | Critical | Credential Access |
| `SL-ENDPOINT-002` | Suspicious PowerShell execution | High | Execution |
| `SL-NET-003` | Internal port scan pattern | High | Discovery |
| `SL-C2-004` | Potential beaconing connection | Medium | Command and Control |

The sample dataset produces:

```text
14 events processed
4 alerts generated
1 critical alert
2 high alerts
```

---

## Sample Report

Reports are generated in the `reports/` folder:

```text
reports/
└── sentinellab-report-20260612-110704.md
```

Generate a report through the API:

```bash
curl -X POST http://localhost:8000/reports
```

The report includes:

- Executive summary
- Alert severity breakdown
- Priority alert details
- Evidence counts
- Recommended next steps

---

## Detection Rule Example

Rules live in `rules/detections.yml`:

```yaml
- id: SL-AUTH-001
  name: Possible brute force against VPN
  severity: critical
  tactic: Credential Access
  event_type: auth
  conditions:
    status: failure
    action: vpn_login
  threshold: 5
  window_minutes: 10
  group_by:
    - src_ip
    - username
```

---

## File Triage Example

Use the frontend **File Triage** tab or call the API:

```bash
curl -X POST http://localhost:8000/analyze-file \
  -F "file=@samples/files/suspicious_script.txt"
```

The analyzer returns:

- SHA256 hash
- File size
- Shannon entropy
- Extracted printable strings
- Suspicious string matches
- Risk score and classification

---

## Demo Script

1. Start the API and frontend.
2. Open the SOC dashboard and show the metrics cards.
3. Explain the critical brute-force alert.
4. Open the **Rules** tab and show that detections are YAML-backed.
5. Open **File Triage** and upload `samples/files/suspicious_script.txt`.
6. Generate a Markdown report from `/reports`.
7. Show the architecture notes in `docs/ARCHITECTURE.md`.

---

## Legal Disclaimer

**SentinelLab is for defensive security education, portfolio demonstration, and authorized lab use only.**

All included telemetry and files are synthetic and safe. Do not use this project to process data, files, systems, or logs you are not authorized to analyze.

---

## Extending

### Add a new detection rule

Add a rule to `rules/detections.yml`:

```yaml
- id: SL-CUSTOM-001
  name: Suspicious administrative login
  description: Admin account logged in from an unusual source.
  severity: high
  tactic: Initial Access
  event_type: auth
  conditions:
    username: admin
    status: success
  tags:
    - identity
    - admin
```

### Use the detection engine as a library

```python
from pathlib import Path
from app.rule_engine import load_rules, normalize_event, run_rules

rules = load_rules(Path("rules"))
events = [normalize_event(raw_event)]
alerts = run_rules(events, rules)
```

---

## References

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rules](https://sigmahq.io/)
- [NIST Incident Response Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

---

## License

This project is licensed under the MIT License.
