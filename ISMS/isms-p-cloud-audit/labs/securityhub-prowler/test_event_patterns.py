"""Test sample CSPM and Inspector finding filters without deploying rules."""

import argparse
import json
import subprocess


def test(pattern, detail, expected, profile, region):
    event = {
        "version": "0",
        "id": "00000000-0000-4000-8000-000000000001",
        "source": pattern["source"][0],
        "detail-type": pattern["detail-type"][0],
        "account": "111122223333",
        "region": region,
        "time": "2026-01-01T00:00:00Z",
        "resources": [],
        "detail": detail,
    }
    output = subprocess.check_output([
        "aws", "events", "test-event-pattern", "--profile", profile, "--region", region,
        "--event-pattern", json.dumps(pattern), "--event", json.dumps(event),
        "--query", "Result", "--output", "json",
    ])
    actual = json.loads(output)
    if actual is not expected:
        raise SystemExit(f"{event['detail-type']}: expected {expected}, got {actual}")
    print(f"{event['detail-type']}: matched={actual}, expected={expected}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="twodragon")
    parser.add_argument("--region", default="ap-northeast-2")
    args = parser.parse_args()
    severities = ["HIGH", "CRITICAL"]
    cspm = {
        "source": ["aws.securityhub"],
        "detail-type": ["Security Hub Findings - Imported"],
        "detail": {"findings": {"Severity": {"Label": severities}}},
    }
    inspector = {
        "source": ["aws.inspector2"],
        "detail-type": ["Inspector2 Finding"],
        "detail": {"severity": severities, "status": ["ACTIVE"]},
    }
    cases = [
        (cspm, {"findings": [{"Severity": {"Label": "HIGH"}}]}, True),
        (cspm, {"findings": [{"Severity": {"Label": "MEDIUM"}}]}, False),
        (inspector, {"severity": "CRITICAL", "status": "ACTIVE"}, True),
        (inspector, {"severity": "MEDIUM", "status": "ACTIVE"}, False),
        (inspector, {"severity": "HIGH", "status": "CLOSED"}, False),
    ]
    for pattern, detail, expected in cases:
        test(pattern, detail, expected, args.profile, args.region)


if __name__ == "__main__":
    main()
