from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

from .models import FileAnalysis, FileFinding


SUSPICIOUS_TERMS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "downloadstring",
    "virtualalloc",
    "createremotethread",
    "mimikatz",
    "lsass",
    "http://",
    "https://",
]


def analyze_file(filename: str, content: bytes) -> FileAnalysis:
    digest = hashlib.sha256(content).hexdigest()
    entropy = _entropy(content)
    extracted_strings = _extract_strings(content)
    lower_strings = " ".join(extracted_strings).lower()
    findings: list[FileFinding] = []
    risk_score = 0

    if entropy >= 7.2:
        risk_score += 30
        findings.append(
            FileFinding(
                label="High entropy",
                severity="high",
                detail="The file has entropy commonly associated with packed or encrypted content.",
            )
        )

    hits = [term for term in SUSPICIOUS_TERMS if term in lower_strings]
    if hits:
        risk_score += min(45, len(hits) * 9)
        findings.append(
            FileFinding(
                label="Suspicious strings",
                severity="medium" if len(hits) < 4 else "high",
                detail=f"Matched indicators: {', '.join(sorted(hits))}.",
            )
        )

    if re.search(rb"MZ.{0,128}PE\x00\x00", content, re.DOTALL):
        risk_score += 15
        findings.append(
            FileFinding(
                label="Portable Executable",
                severity="medium",
                detail="The file contains PE headers and should be triaged in a sandbox.",
            )
        )

    classification = "benign"
    if risk_score >= 70:
        classification = "high-risk"
    elif risk_score >= 35:
        classification = "suspicious"
    elif risk_score >= 15:
        classification = "requires-review"

    return FileAnalysis(
        filename=filename,
        size_bytes=len(content),
        sha256=digest,
        entropy=round(entropy, 3),
        risk_score=min(risk_score, 100),
        classification=classification,
        strings=extracted_strings[:40],
        findings=findings,
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _extract_strings(data: bytes) -> list[str]:
    matches = re.findall(rb"[\x20-\x7E]{4,}", data)
    return [match.decode("utf-8", errors="ignore") for match in matches]

