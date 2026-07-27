import io
import json
from unittest.mock import patch

import main


def test_normalize_sonar_maps_fields():
    issue = {
        "message": "Unsanitized input reaches SQL query",
        "severity": "CRITICAL",
        "component": "vulnity:server.js",
        "line": 88,
    }
    normalized = main.normalize_sonar(issue)

    assert normalized == {
        "source": "SAST",
        "name": "Unsanitized input reaches SQL query",
        "severity": "CRITICAL",
        "file": "vulnity:server.js",
        "line": 88,
        "description": "Unsanitized input reaches SQL query",
    }


def test_normalize_nuclei_reads_jsonl_and_maps_fields():
    sample_lines = "\n".join(
        [
            json.dumps(
                {
                    "template-id": "xss-reflection",
                    "matched-at": "http://target/search?q=test",
                    "info": {"severity": "medium"},
                }
            ),
            json.dumps(
                {
                    "template-id": "missing-security-headers",
                    "matched-at": "http://target/",
                    "info": {"severity": "low"},
                }
            ),
        ]
    )

    def fake_exists(path):
        return path == "/app/shared/nuclei_results.json"

    with patch("main.os.path.exists", side_effect=fake_exists), patch(
        "builtins.open", return_value=io.StringIO(sample_lines)
    ):
        normalized = main.normalize_nuclei()

    assert len(normalized) == 2
    assert normalized[0] == {
        "source": "DAST",
        "tool": "nuclei",
        "name": "xss-reflection",
        "severity": "medium",
        "url": "http://target/search?q=test",
    }


def test_normalize_trivy_extracts_vulnerabilities():
    sample_trivy = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1111",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.0",
                        "Severity": "HIGH",
                        "Title": "Prototype pollution",
                    }
                ],
            }
        ]
    }

    def fake_exists(path):
        return path == "/app/shared/trivy_results.json"

    with patch("main.os.path.exists", side_effect=fake_exists), patch(
        "builtins.open", return_value=io.StringIO(json.dumps(sample_trivy))
    ):
        normalized = main.normalize_trivy()

    assert len(normalized) == 1
    assert normalized[0]["source"] == "SCA"
    assert normalized[0]["tool"] == "trivy"
    assert normalized[0]["name"] == "CVE-2024-1111 in lodash"
    assert normalized[0]["severity"] == "HIGH"
    assert normalized[0]["file"] == "package-lock.json"
