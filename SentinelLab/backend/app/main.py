from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .file_analyzer import analyze_file
from .models import Alert, FileAnalysis, SecurityEvent, SocSummary
from .reporting import build_markdown_report, save_report
from .rule_engine import load_rules, normalize_event, run_rules, summarize


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = PROJECT_ROOT / "rules"
SAMPLE_LOG = PROJECT_ROOT / "samples" / "logs" / "security_events.jsonl"
REPORT_DIR = PROJECT_ROOT / "reports"

app = FastAPI(
    title="SentinelLab API",
    version="1.0.0",
    description="Mini-SIEM and static file triage platform for cybersecurity portfolios.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_events() -> list[SecurityEvent]:
    if not SAMPLE_LOG.exists():
        return []
    events = []
    for line in SAMPLE_LOG.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(normalize_event(json.loads(line)))
    return events


def get_alerts() -> list[Alert]:
    return run_rules(get_events(), load_rules(RULES_DIR))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/events", response_model=list[SecurityEvent])
def events() -> list[SecurityEvent]:
    return get_events()


@app.get("/rules")
def rules() -> list[dict]:
    return [rule.model_dump() for rule in load_rules(RULES_DIR)]


@app.get("/alerts", response_model=list[Alert])
def alerts() -> list[Alert]:
    return get_alerts()


@app.get("/summary", response_model=SocSummary)
def summary() -> dict:
    events_payload = get_events()
    alerts_payload = run_rules(events_payload, load_rules(RULES_DIR))
    return summarize(events_payload, alerts_payload)


@app.post("/ingest", response_model=list[Alert])
async def ingest_log(file: UploadFile = File(...)) -> list[Alert]:
    content = await file.read()
    try:
        events_payload = [normalize_event(json.loads(line)) for line in content.decode("utf-8").splitlines() if line.strip()]
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Upload must be UTF-8 JSONL security events.") from exc
    return run_rules(events_payload, load_rules(RULES_DIR))


@app.post("/analyze-file", response_model=FileAnalysis)
async def analyze_uploaded_file(file: UploadFile = File(...)) -> FileAnalysis:
    content = await file.read()
    return analyze_file(file.filename or "upload.bin", content)


@app.post("/reports")
def create_report() -> dict[str, str]:
    events_payload = get_events()
    alerts_payload = get_alerts()
    report = build_markdown_report(events_payload, alerts_payload)
    output = save_report(REPORT_DIR, report)
    return {"path": str(output), "markdown": report}
