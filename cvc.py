# cvc.py  -  Classification, Deduplication, and Prioritization of security findings.

import hashlib
import pickle
from functools import lru_cache

# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

SEVERITY_MAP: dict[str, int] = {
    "INFO": 1,
    "LOW": 2,
    "MINOR": 3,
    "MEDIUM": 5,
    "MAJOR": 6,
    "HIGH": 8,
    "CRITICAL": 10,
}

TOOL_EXPLOIT_BONUS: dict[str, int] = {
    "metasploit": 5,
    "sqlmap": 4,
    "trivy": 3,
    "nuclei": 3,
    "nikto": 2,
    "zap": 1,
    "semgrep": 1,
}

CORROBORATION_BONUS_PER_EXTRA_TOOL = 1
MAX_CORROBORATION_BONUS = 4

# OWASP category → numeric encoding for scoring
OWASP_CATEGORY_MAP: dict[str, int] = {
    "Injection - SQL":             1,
    "Injection - LDAP":            1,
    "Injection - Command":         1,
    "Broken Authentication":       2,
    "Cross-Site Scripting":        3,
    "XML External Entity":         4,
    "Broken Access Control":       5,
    "Security Misconfiguration":   6,
    "Known Vulnerable Component":  7,
    "Cross-Site Request Forgery":  8,
    "Server-Side Request Forgery": 9,
    "Remote Code Execution":       10,
    "Path Traversal":              11,
    "Open Redirect":               12,
    "Other":                       0,
}

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

_CLASSIFICATION_RULES: list[tuple[str, str]] = [
    ("sql", "Injection - SQL"),
    ("sqli", "Injection - SQL"),
    ("ldap inject", "Injection - LDAP"),
    ("command inject", "Injection - Command"),
    ("rce", "Remote Code Execution"),
    ("xss", "Cross-Site Scripting"),
    ("csrf", "Cross-Site Request Forgery"),
    ("xxe", "XML External Entity"),
    ("ssrf", "Server-Side Request Forgery"),
    ("idor", "Broken Access Control"),
    ("path traversal", "Path Traversal"),
    ("open redirect", "Open Redirect"),
    ("header", "Security Misconfiguration"),
    ("tls", "Security Misconfiguration"),
    ("ssl", "Security Misconfiguration"),
    ("cors", "Security Misconfiguration"),
    ("auth", "Broken Authentication"),
    ("jwt", "Broken Authentication"),
    ("token", "Broken Authentication"),
    ("cve-", "Known Vulnerable Component"),
    ("outdated", "Known Vulnerable Component"),
    ("dependency", "Known Vulnerable Component"),
]


def classify(issue: dict) -> str:
    """Return a category string for a finding."""
    name = issue.get("name", "").lower()
    for keyword, category in _CLASSIFICATION_RULES:
        if keyword in name:
            return category
    return "Other"


# ---------------------------------------------------------------------------
# Deduplication / correlation
# ---------------------------------------------------------------------------

def _correlation_key(issue: dict) -> str:
    """
    Build a stable key for what the finding is + where it is, independent of tool.
    Fixed: findings with no CWE/CVE/name no longer hash to the same empty key.
    """
    parts: list[str] = []

    cwe      = (issue.get("cwe") or "").strip().upper()
    cve      = (issue.get("cve") or "").strip().upper()
    name     = (issue.get("name") or "").strip().lower()
    endpoint = (
        issue.get("endpoint") or issue.get("url") or issue.get("file") or ""
    ).strip().lower()

    line = issue.get("line") or issue.get("line_number") or 0
    try:
        line_bucket = (int(line) // 10) * 10
    except (ValueError, TypeError):
        line_bucket = 0

    if cwe:
        parts.append(cwe)
    if cve:
        parts.append(cve)
    if not parts:
        if name:
            parts.append(name)
        else:
            # Guaranteed unique — prevents unrelated findings merging
            parts.append(f"__unknown_{id(issue)}")

    parts.append(endpoint or "__no_location")
    parts.append(str(line_bucket))

    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def deduplicate(issues: list[dict]) -> list[dict]:
    """
    Merge findings that share the same correlation key.
    """
    buckets: dict[str, dict] = {}

    for issue in issues:
        key = _correlation_key(issue)
        tool_name = issue.get("tool", "unknown")
        sev_name  = issue.get("severity", "INFO").upper()

        if key not in buckets:
            merged = dict(issue)
            merged["_corr_key"]        = key
            merged["_source_tools"]    = {tool_name}
            merged["_raw_severities"]  = {sev_name}
            buckets[key] = merged
            continue

        merged = buckets[key]
        merged["_source_tools"].add(tool_name)
        merged["_raw_severities"].add(sev_name)

        current_score  = SEVERITY_MAP.get(merged.get("severity", "INFO").upper(), 1)
        incoming_score = SEVERITY_MAP.get(sev_name, 1)
        if incoming_score > current_score:
            merged["severity"]    = issue.get("severity", merged.get("severity"))
            merged["description"] = issue.get("description", merged.get("description", ""))

        for field in ("cwe", "cve", "endpoint", "url", "file"):
            if not merged.get(field) and issue.get(field):
                merged[field] = issue[field]

    result = []
    for merged in buckets.values():
        merged["source_tools"]   = sorted(merged.pop("_source_tools"))
        merged["raw_severities"] = sorted(merged.pop("_raw_severities"))
        merged.pop("_corr_key", None)
        merged.pop("tool", None)
        result.append(merged)

    return result


# ---------------------------------------------------------------------------
# Enrichment from lookups.pkl (no live API calls)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _load_lookups(path: str = "lookups.pkl") -> dict:
    """Load pre-built lookup tables once, cache in memory."""
    with open(path, "rb") as f:
        return pickle.load(f)


def enrich_with_scores(issues: list[dict],
                       lookups_path: str = "lookups.pkl") -> list[dict]:
    """
    Stamp each finding with CVSS, EPSS, KEV, and OWASP data from lookups.pkl.
    No network calls — lookups.pkl is built once by build_lookups.py.

    After this runs, every finding has:
      cvss_score, epss_score, epss_percentile,
      is_kev, kev_ransomware, attack_vector,
      owasp_category, owasp_encoded, cwe_abstraction
    """
    lk      = _load_lookups(lookups_path)
    epss_lk = lk.get("epss", {})
    kev_lk  = lk.get("kev",  {})
    nvd_lk  = lk.get("nvd",  lk.get("cve", {}))  # support both key names
    cwe_lk  = lk.get("cwe",  {})

    for issue in issues:
        cve = (issue.get("cve") or "").strip().upper()
        cwe = (issue.get("cwe") or "").strip().upper()

        # ── CVE-based enrichment ────────────────────────────────────────
        if cve.startswith("CVE-"):
            epss_rec = epss_lk.get(cve, {})
            kev_rec  = kev_lk.get(cve,  {})
            nvd_rec  = nvd_lk.get(cve,  {})

            issue["cvss_score"]      = nvd_rec.get("cvss", 0.0)
            issue["epss_score"]      = epss_rec.get("epss",
                                       nvd_rec.get("epss", 0.0))
            issue["epss_percentile"] = epss_rec.get("percentile",
                                       nvd_rec.get("epss_percentile", 0.0))
            issue["is_kev"]          = kev_rec.get("is_kev",
                                       nvd_rec.get("is_kev", 0))
            issue["kev_ransomware"]  = kev_rec.get("kev_ransomware",
                                       nvd_rec.get("kev_ransomware", 0))
            issue["attack_vector"]   = nvd_rec.get("attack_vector", 0)

            # If tool didn't supply CWE but NVD has it, fill it in
            if not cwe and nvd_rec.get("cwe_id"):
                cwe = nvd_rec["cwe_id"]
                issue["cwe"] = cwe
        else:
            issue["cvss_score"]      = 0.0
            issue["epss_score"]      = 0.0
            issue["epss_percentile"] = 0.0
            issue["is_kev"]          = 0
            issue["kev_ransomware"]  = 0
            issue["attack_vector"]   = 0

        # ── CWE-based enrichment (works even without a CVE) ────────────
        if cwe.startswith("CWE-"):
            cwe_rec = cwe_lk.get(cwe, {})
            issue["owasp_category"]  = cwe_rec.get("owasp_category", "Other")
            issue["owasp_encoded"]   = cwe_rec.get("owasp_encoded",  0)
            issue["cwe_abstraction"] = cwe_rec.get("abstraction_level", 1)
        else:
            # Fall back to keyword classifier
            category = issue.get("category") or classify(issue)
            issue["owasp_category"]  = category
            issue["owasp_encoded"]   = OWASP_CATEGORY_MAP.get(category, 0)
            issue["cwe_abstraction"] = 1

    return issues


# ---------------------------------------------------------------------------
# Prioritization (rule-based, no model)
# ---------------------------------------------------------------------------

ASSET_KEYWORDS = ("auth", "payment", "admin", "session", "login", "oauth")

def _rule_score(issue: dict) -> float:
    """
    Weighted rule-based score. All signals are additive.
    Tune the weights here — no retraining needed.
    """
    score = 0.0

    # ── Base severity (from your SEVERITY_MAP) ──────────────────────────
    score += SEVERITY_MAP.get(issue.get("severity", "INFO").upper(), 1)

    # ── CVSS ────────────────────────────────────────────────────────────
    cvss = float(issue.get("cvss_score") or 0.0)
    if cvss >= 9.0:   score += 3.0
    elif cvss >= 7.0: score += 2.0
    elif cvss >= 4.0: score += 1.0

    # ── EPSS ────────────────────────────────────────────────────────────
    epss     = float(issue.get("epss_score")       or 0.0)
    epss_pct = float(issue.get("epss_percentile")  or 0.0)
    if epss > 0.50:   score += 2.0
    elif epss > 0.10: score += 1.0
    score += epss_pct * 1.0          # continuous 0–1 bonus

    # ── KEV ─────────────────────────────────────────────────────────────
    if issue.get("is_kev"):         score += 3.0
    if issue.get("kev_ransomware"): score += 1.0

    # ── Tool signals (your existing bonuses, kept as-is) ────────────────
    source_tools = issue.get("source_tools", [])
    score += _exploit_bonus(source_tools)
    score += _corroboration_bonus(source_tools)

    # ── Network-reachable attack vector ─────────────────────────────────
    if int(issue.get("attack_vector") or 0) == 2:
        score += 1.0

    # ── Sensitive asset context ──────────────────────────────────────────
    fp = (issue.get("file") or issue.get("endpoint") or "").lower()
    if any(k in fp for k in ASSET_KEYWORDS):
        score += 1.0

    # ── Regression: seen in a prior scan ────────────────────────────────
    if issue.get("seen_before"):
        score += 1.0

    # ── CWE specificity: variant-level = most actionable ────────────────
    if int(issue.get("cwe_abstraction") or 1) >= 3:
        score += 0.5

    return score


def _exploit_bonus(source_tools: list[str]) -> int:
    return max((TOOL_EXPLOIT_BONUS.get(t.lower(), 0) for t in source_tools), default=0)


def _corroboration_bonus(source_tools: list[str]) -> int:
    extra_tools = max(0, len(source_tools) - 1)
    return min(extra_tools * CORROBORATION_BONUS_PER_EXTRA_TOOL, MAX_CORROBORATION_BONUS)


def prioritize(issues: list[dict],
               lookups_path: str = "lookups.pkl") -> list[dict]:
    """
    Full pipeline: deduplicate → classify → enrich → score → rank.
    This is the only function your CI needs to call.
    """
    deduped = deduplicate(issues)

    for issue in deduped:
        issue["category"] = classify(issue)

    deduped = enrich_with_scores(deduped, lookups_path=lookups_path)

    for issue in deduped:
        score = _rule_score(issue)
        issue["priority_score"]   = score
        issue["score_breakdown"]  = {
            "base_severity":      SEVERITY_MAP.get(
                                      issue.get("severity", "INFO").upper(), 1),
            "cvss_bonus":         3.0 if float(issue.get("cvss_score") or 0) >= 9
                                  else 2.0 if float(issue.get("cvss_score") or 0) >= 7
                                  else 1.0 if float(issue.get("cvss_score") or 0) >= 4
                                  else 0.0,
            "epss_bonus":         2.0 if float(issue.get("epss_score") or 0) > 0.5
                                  else 1.0 if float(issue.get("epss_score") or 0) > 0.1
                                  else 0.0,
            "kev_bonus":          3.0 if issue.get("is_kev") else 0.0,
            "exploit_bonus":      _exploit_bonus(issue.get("source_tools", [])),
            "corroboration_bonus":_corroboration_bonus(issue.get("source_tools", [])),
        }

    deduped.sort(key=lambda x: x["priority_score"], reverse=True)

    for rank, issue in enumerate(deduped):
        issue["rank"] = rank + 1

    return deduped