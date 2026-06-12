from app.file_analyzer import analyze_file


def test_file_analyzer_flags_suspicious_strings():
    payload = b"powershell.exe -w hidden DownloadString https://example.invalid VirtualAlloc"
    analysis = analyze_file("sample.txt", payload)

    assert analysis.risk_score >= 20
    assert analysis.classification in {"requires-review", "suspicious", "high-risk"}
    assert analysis.findings

