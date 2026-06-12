from pathlib import Path

from app.rule_engine import load_rules, normalize_event, run_rules


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_sample_events_generate_expected_alerts():
    rules = load_rules(PROJECT_ROOT / "rules")
    events = [
        normalize_event(__import__("json").loads(line))
        for line in (PROJECT_ROOT / "samples" / "logs" / "security_events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    alerts = run_rules(events, rules)
    rule_ids = {alert.rule_id for alert in alerts}

    assert "SL-AUTH-001" in rule_ids
    assert "SL-ENDPOINT-002" in rule_ids
    assert "SL-NET-003" in rule_ids
    assert "SL-C2-004" in rule_ids

