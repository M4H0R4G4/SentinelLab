from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from .models import Alert, DetectionRule, SecurityEvent


def load_rules(rules_dir: Path) -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    for rule_file in sorted(rules_dir.glob("*.yml")):
        payload = yaml.safe_load(rule_file.read_text(encoding="utf-8")) or {}
        for item in payload.get("rules", []):
            rules.append(DetectionRule.model_validate(item))
    return rules


def normalize_event(raw: dict[str, Any]) -> SecurityEvent:
    metadata = dict(raw)
    for key in [
        "timestamp",
        "src_ip",
        "source_ip",
        "dst_ip",
        "destination_ip",
        "username",
        "hostname",
        "event_type",
        "action",
        "status",
        "process",
        "command_line",
    ]:
        metadata.pop(key, None)

    if "source_ip" in raw and "src_ip" not in raw:
        raw["src_ip"] = raw["source_ip"]
    if "destination_ip" in raw and "dst_ip" not in raw:
        raw["dst_ip"] = raw["destination_ip"]
    raw["metadata"] = metadata
    return SecurityEvent.model_validate(raw)


def run_rules(events: list[SecurityEvent], rules: list[DetectionRule]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        candidates = [event for event in events if _event_matches_rule(event, rule)]
        if not candidates:
            continue

        if rule.threshold and rule.group_by:
            alerts.extend(_threshold_alerts(candidates, rule))
        else:
            alerts.extend(_single_event_alerts(candidates, rule))

    return sorted(alerts, key=lambda alert: _severity_rank(alert.severity), reverse=True)


def summarize(events: list[SecurityEvent], alerts: list[Alert]) -> dict[str, Any]:
    sources = Counter(event.source_ip for event in events)
    hosts = {event.hostname for event in events if event.hostname}
    severities = Counter(alert.severity for alert in alerts)
    tactics = Counter(alert.tactic for alert in alerts)
    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "critical_alerts": severities["critical"],
        "high_alerts": severities["high"],
        "assets": len(hosts),
        "top_sources": [{"ip": ip, "events": count} for ip, count in sources.most_common(5)],
        "alerts_by_severity": dict(severities),
        "alerts_by_tactic": dict(tactics),
    }


def _event_matches_rule(event: SecurityEvent, rule: DetectionRule) -> bool:
    if rule.event_type and event.event_type != rule.event_type:
        return False

    for field, expected in rule.conditions.items():
        value = _get_event_value(event, field)
        if isinstance(expected, list):
            if value not in expected:
                return False
        elif isinstance(expected, dict) and "contains_any" in expected:
            haystack = str(value or "").lower()
            needles = [str(item).lower() for item in expected["contains_any"]]
            if not any(needle in haystack for needle in needles):
                return False
        elif value != expected:
            return False

    return True


def _threshold_alerts(events: list[SecurityEvent], rule: DetectionRule) -> list[Alert]:
    grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        key_parts = [str(_get_event_value(event, field) or "unknown") for field in rule.group_by]
        grouped[" | ".join(key_parts)].append(event)

    alerts: list[Alert] = []
    for entity, evidence in grouped.items():
        evidence = sorted(evidence, key=lambda item: item.timestamp)
        if len(evidence) < (rule.threshold or 1):
            continue
        if rule.window_minutes and not _within_window(evidence, rule.window_minutes):
            continue
        alerts.append(_build_alert(rule, entity, evidence))
    return alerts


def _single_event_alerts(events: list[SecurityEvent], rule: DetectionRule) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        entity = event.hostname or event.username or event.source_ip
        alerts.append(_build_alert(rule, entity, [event]))
    return alerts


def _build_alert(rule: DetectionRule, entity: str, evidence: list[SecurityEvent]) -> Alert:
    return Alert(
        id=f"AL-{uuid4().hex[:8].upper()}",
        rule_id=rule.id,
        title=rule.name,
        severity=rule.severity,
        tactic=rule.tactic,
        description=rule.description,
        created_at=datetime.now(UTC),
        entity=entity,
        evidence_count=len(evidence),
        evidence=evidence,
        tags=rule.tags,
    )


def _within_window(events: list[SecurityEvent], minutes: int) -> bool:
    return (events[-1].timestamp - events[0].timestamp).total_seconds() <= minutes * 60


def _get_event_value(event: SecurityEvent, field: str) -> Any:
    if hasattr(event, field):
        return getattr(event, field)
    if field == "src_ip":
        return event.source_ip
    if field == "dst_ip":
        return event.destination_ip
    return event.metadata.get(field)


def _severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)
