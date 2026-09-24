#!/usr/bin/env python3
"""Convert an OWASP ZAP baseline JSON report into SARIF.

zap-baseline.py has no native SARIF writer (only HTML/Markdown/XML/JSON), and
every other stage in this pipeline reports as SARIF so the policy gate and
GitHub code scanning have one shape to read. This script bridges that gap.

ZAP risk codes: 0 Informational, 1 Low, 2 Medium, 3 High.
Mapped to SARIF levels: High -> error, Medium -> warning, else -> note.
"""

import json
import sys
from urllib.parse import urlparse

RISK_TO_LEVEL = {"3": "error", "2": "warning"}


def as_relative_path(uri: str) -> str:
    """GitHub code scanning rejects http(s):// artifactLocation URIs when the
    checkout scheme is "file" (SARIF URI scheme mismatch). DAST has no source
    file to point at, so turn the target URL into a synthetic relative path
    instead of a real absolute URI."""
    parsed = urlparse(uri)
    path = parsed.path.lstrip("/") or "index"
    return f"dast-targets/{parsed.netloc}/{path}"


def convert(zap_report: dict) -> dict:
    rules = {}
    results = []

    for site in zap_report.get("site", []):
        for alert in site.get("alerts", []):
            rule_id = alert.get("alertRef") or alert.get("pluginid") or alert["name"]
            level = RISK_TO_LEVEL.get(str(alert.get("riskcode", "0")), "note")

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": alert["name"],
                    "shortDescription": {"text": alert["name"]},
                    "fullDescription": {"text": alert.get("desc", alert["name"])},
                    "help": {"text": alert.get("solution", "")},
                    "properties": {"tags": ["security", "dast", "owasp-zap"]},
                }

            instances = alert.get("instances", [{"uri": site.get("@name", "")}])
            for instance in instances:
                results.append(
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {"text": alert.get("desc", alert["name"])},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": as_relative_path(
                                            instance.get("uri", site.get("@name", ""))
                                        ),
                                    }
                                }
                            }
                        ],
                    }
                )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP ZAP",
                        "informationUri": "https://www.zaproxy.org/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: zap_to_sarif.py <zap-report.json> <output.sarif>", file=sys.stderr)
        sys.exit(2)

    with open(sys.argv[1], encoding="utf-8") as f:
        report = json.load(f)

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(convert(report), f, indent=2)
