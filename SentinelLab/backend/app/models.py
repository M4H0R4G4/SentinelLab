from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]


class SecurityEvent(BaseModel):
    timestamp: datetime
    source_ip: str = Field(alias="src_ip")
    destination_ip: str | None = Field(default=None, alias="dst_ip")
    username: str | None = None
    hostname: str | None = None
    event_type: str
    action: str | None = None
    status: str | None = None
    process: str | None = None
    command_line: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    tactic: str
    event_type: str | None = None
    conditions: dict[str, Any] = Field(default_factory=dict)
    threshold: int | None = None
    window_minutes: int | None = None
    group_by: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    tactic: str
    description: str
    created_at: datetime
    entity: str
    evidence_count: int
    evidence: list[SecurityEvent]
    tags: list[str] = Field(default_factory=list)
    status: Literal["open", "investigating", "closed"] = "open"


class FileFinding(BaseModel):
    label: str
    severity: Severity
    detail: str


class FileAnalysis(BaseModel):
    filename: str
    size_bytes: int
    sha256: str
    entropy: float
    risk_score: int
    classification: str
    strings: list[str]
    findings: list[FileFinding]


class SocSummary(BaseModel):
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    assets: int
    top_sources: list[dict[str, Any]]
    alerts_by_severity: dict[str, int]
    alerts_by_tactic: dict[str, int]

