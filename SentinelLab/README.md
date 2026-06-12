# SentinelLab

SentinelLab is a professional cybersecurity portfolio project: a lightweight SOC platform with SIEM-style detections, file triage, alert investigation and report generation.

## What It Shows

- Detection engineering with YAML rules.
- FastAPI backend design.
- Static file triage using hashes, entropy and suspicious strings.
- SOC dashboard with alert queue, event timeline and rule catalog.
- Dockerized demo environment.
- Clean documentation for GitHub and interviews.

## Features

- Brute-force detection against VPN authentication logs.
- Suspicious PowerShell execution detection.
- Internal port scan detection.
- Potential DNS beaconing detection.
- Upload endpoint for JSONL event ingestion.
- File analysis endpoint with SHA256, entropy, strings and risk scoring.
- Markdown incident report generation.

## Project Structure

```txt
SentinelLab/
  backend/        FastAPI API, detection engine, file analyzer and tests
  frontend/       SOC dashboard
  rules/          YAML detection rules
  samples/        Safe telemetry and triage demo files
  reports/        Generated Markdown reports
  docs/           Architecture notes
```

## Run Locally

### Option 1: Docker Compose

```bash
docker compose up --build
```

- Frontend: http://localhost:8080
- API docs: http://localhost:8000/docs

### Option 2: Python API + Static Frontend

```bash
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open `frontend/index.html` in your browser.

## API Endpoints

- `GET /health`
- `GET /events`
- `GET /rules`
- `GET /alerts`
- `GET /summary`
- `POST /ingest`
- `POST /analyze-file`
- `POST /reports`

## Demo Script

1. Start the API and frontend.
2. Open the dashboard and show critical/high alerts.
3. Explain the brute-force alert evidence from `samples/logs/security_events.jsonl`.
4. Open the Rules tab and show the YAML-backed detections.
5. Upload `samples/files/suspicious_script.txt` in File Triage.
6. Generate a Markdown report and show the output in `reports/`.

## Safety Notice

All telemetry and files in this repository are synthetic and safe for demonstration. The project is designed for defensive security education and portfolio presentation.

