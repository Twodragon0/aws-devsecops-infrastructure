"""Summarize explicitly supplied, synthetic findings without calling AWS APIs."""

from collections import Counter


def lambda_handler(event, _context):
    findings = event.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")

    counts = Counter()
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("each finding must be an object")
        severity = finding.get("severity", "UNKNOWN")
        if not isinstance(severity, str):
            raise ValueError("severity must be a string")
        counts[severity.upper()] += 1

    return {
        "source": "supplied synthetic training event",
        "total": len(findings),
        "by_severity": dict(sorted(counts.items())),
        "high_priority": counts["HIGH"] + counts["CRITICAL"],
    }
