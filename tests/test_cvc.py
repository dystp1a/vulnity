from cvc import classify, deduplicate, prioritize


def test_classify_sql_injection():
    issue = {"name": "Possible SQL injection in search endpoint"}
    assert classify(issue) == "Injection - SQL"


def test_deduplicate_merges_same_vuln_and_keeps_highest_severity():
    issues = [
        {
            "source": "SAST",
            "tool": "semgrep",
            "name": "SQL Injection",
            "severity": "MEDIUM",
            "file": "app.js",
            "line": 42,
            "description": "Pattern match",
        },
        {
            "source": "Pentest",
            "tool": "sqlmap",
            "name": "SQL Injection",
            "severity": "CRITICAL",
            "file": "app.js",
            "line": 44,  # same 10-line bucket as line 42
            "description": "Confirmed injectable",
        },
    ]

    deduped = deduplicate(issues)
    assert len(deduped) == 1

    merged = deduped[0]
    assert merged["severity"].upper() == "CRITICAL"
    assert merged["source_tools"] == ["semgrep", "sqlmap"]
    assert merged["raw_severities"] == ["CRITICAL", "MEDIUM"]
    assert "tool" not in merged


def test_prioritize_adds_exploit_and_corroboration_bonus():
    issues = [
        {
            "source": "SAST",
            "tool": "semgrep",
            "name": "SQL Injection",
            "severity": "HIGH",
            "file": "api.js",
            "line": 10,
            "description": "Potential SQLi",
        },
        {
            "source": "Pentest",
            "tool": "sqlmap",
            "name": "SQL Injection",
            "severity": "HIGH",
            "file": "api.js",
            "line": 13,  # same bucket
            "description": "Confirmed SQLi",
        },
    ]

    ranked = prioritize(issues)
    assert len(ranked) == 1

    finding = ranked[0]
    # base HIGH=8, exploit=max(semgrep=1, sqlmap=4)=4, corroboration=1 -> total 13
    assert finding["priority_score"] == 13
    assert finding["score_breakdown"] == {
        "base_severity": 8,
        "exploit_bonus": 4,
        "corroboration_bonus": 1,
    }
    assert finding["category"] == "Injection - SQL"
