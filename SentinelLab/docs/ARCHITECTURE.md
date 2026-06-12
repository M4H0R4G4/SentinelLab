# SentinelLab Architecture

SentinelLab is a portfolio-ready defensive security project that models a lightweight SOC platform.

## Components

- `frontend`: Static dashboard for SOC monitoring, alert triage, file analysis and rule browsing.
- `backend`: FastAPI service exposing events, alerts, rules, file analysis and report generation.
- `rules`: YAML detection rules loaded at runtime.
- `samples`: JSONL security telemetry and safe demo files.
- `reports`: Generated Markdown incident reports.

## Detection Flow

1. Raw JSONL events are loaded or uploaded.
2. Events are normalized into a consistent security event model.
3. YAML rules are evaluated using exact, contains-any and threshold-window logic.
4. Alerts are ranked by severity and exposed through the API.
5. Reports summarize executive risk and investigation evidence.

## Portfolio Talking Points

- Rule-driven detection design similar to SIEM workflows.
- Separation between API, detection logic, file triage and presentation layer.
- Safe sample telemetry that demonstrates brute force, suspicious execution, port scan and DNS beaconing.
- Docker Compose setup for reproducible local demos.

