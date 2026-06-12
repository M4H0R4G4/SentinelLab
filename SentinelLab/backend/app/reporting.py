from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .models import Alert, FileAnalysis, SecurityEvent
from .rule_engine import summarize


def build_markdown_report(events: list[SecurityEvent], alerts: list[Alert], file_analysis: FileAnalysis | None = None) -> str:
    summary = summarize(events, alerts)
    lines = [
        "# SentinelLab Security Report",
        "",
        f"Generated at: {datetime.now(UTC).isoformat(timespec='seconds')}",
        "",
        "## Executive Summary",
        "",
        f"- Events processed: {summary['total_events']}",
        f"- Alerts generated: {summary['total_alerts']}",
        f"- Critical alerts: {summary['critical_alerts']}",
        f"- High alerts: {summary['high_alerts']}",
        f"- Assets observed: {summary['assets']}",
        "",
        "## Priority Alerts",
        "",
    ]

    if not alerts:
        lines.append("No alerts were generated for this dataset.")
    for alert in alerts[:10]:
        lines.extend(
            [
                f"### {alert.title}",
                "",
                f"- Severity: {alert.severity}",
                f"- Tactic: {alert.tactic}",
                f"- Entity: {alert.entity}",
                f"- Evidence count: {alert.evidence_count}",
                f"- Description: {alert.description}",
                "",
            ]
        )

    if file_analysis:
        lines.extend(
            [
                "## File Analysis",
                "",
                f"- Filename: {file_analysis.filename}",
                f"- SHA256: `{file_analysis.sha256}`",
                f"- Entropy: {file_analysis.entropy}",
                f"- Risk score: {file_analysis.risk_score}/100",
                f"- Classification: {file_analysis.classification}",
                "",
            ]
        )
        for finding in file_analysis.findings:
            lines.append(f"- {finding.severity.upper()}: {finding.label} - {finding.detail}")

    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "",
            "- Validate high and critical alerts with endpoint telemetry.",
            "- Enrich source IPs with threat intelligence and geolocation.",
            "- Preserve evidence and timeline for incident response handoff.",
            "- Tune detection rules based on confirmed false positives.",
        ]
    )
    return "\n".join(lines)


def save_report(report_dir: Path, content: str) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    output = report_dir / f"sentinellab-report-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.md"
    output.write_text(content, encoding="utf-8")
    return output
