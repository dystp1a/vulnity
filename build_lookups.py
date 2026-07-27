# build_lookups.py
"""
Sources:
  CVE data   → Kaggle CSV (155k entries, local file)
               columns: cve_id, base_severity, base_score, exploitability_score,
                        impact_score, epss_score, epss_perc, cisa_kev,
                        attack_vector, attack_complexity
  CVE→CWE    → stasvinokur/cve-and-cwe-dataset-1999-2025 (HuggingFace)
  CWE details → MITRE CSV zip (Name, Description, Weakness Abstraction)
                falls back to hardcoded table if unreachable

Run:
  python build_lookups.py kaggle.csv
"""

import io, pickle, sys, zipfile
import requests
import pandas as pd
from datasets import load_dataset


# ---------------------------------------------------------------------------
# Encoding maps
# ---------------------------------------------------------------------------

ATTACK_VECTOR_MAP = {
    "NETWORK":          2,
    "ADJACENT":         1,
    "ADJACENT_NETWORK": 1,
    "LOCAL":            0,
    "PHYSICAL":         0,
}

ATTACK_COMPLEXITY_MAP = {
    "LOW":  1,
    "HIGH": 0,
}

OWASP_CATEGORY_MAP_NUMERIC = {
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

CWE_OWASP_RULES = [
    ("sql inject",          "Injection - SQL"),
    ("ldap inject",         "Injection - LDAP"),
    ("os command",          "Injection - Command"),
    ("command inject",      "Injection - Command"),
    ("remote code",         "Remote Code Execution"),
    ("code inject",         "Remote Code Execution"),
    ("cross-site script",   "Cross-Site Scripting"),
    ("csrf",                "Cross-Site Request Forgery"),
    ("forgery",             "Cross-Site Request Forgery"),
    ("xml external",        "XML External Entity"),
    ("server-side request", "Server-Side Request Forgery"),
    ("ssrf",                "Server-Side Request Forgery"),
    ("path traversal",      "Path Traversal"),
    ("directory traversal", "Path Traversal"),
    ("open redirect",       "Open Redirect"),
    ("access control",      "Broken Access Control"),
    ("privilege",           "Broken Access Control"),
    ("authenticat",         "Broken Authentication"),
    ("session",             "Broken Authentication"),
    ("jwt",                 "Broken Authentication"),
    ("tls",                 "Security Misconfiguration"),
    ("ssl",                 "Security Misconfiguration"),
    ("cors",                "Security Misconfiguration"),
    ("misconfigur",         "Security Misconfiguration"),
    ("outdated",            "Known Vulnerable Component"),
    ("dependency",          "Known Vulnerable Component"),
]

CWE_ABSTRACTION_MAP = {
    "pillar":   0,
    "class":    1,
    "base":     2,
    "variant":  3,
    "compound": 2,
}

# FIX #6: Explicit required column list — validated before processing.
# Different Kaggle CVE datasets use slightly different column names.
# Without this check, a missing column silently creates an all-NaN series,
# causing epss_percentile and other enrichment to return 0.0 for everything.
REQUIRED_COLUMNS = [
    "cve_id",
    "base_score",
    "epss_score",
    "cisa_kev",
    "attack_vector",
]

# FIX #6: Known alternative column name spellings across Kaggle CVE datasets.
# If a required column is missing, we check these aliases before failing.
COLUMN_ALIASES = {
    "epss_score"    : ["epss", "epss_score", "EPSS_Score"],
    "epss_perc"     : ["epss_perc", "epss_percentile", "percentile", "EPSS_Percentile"],
    "cisa_kev"      : ["cisa_kev", "cisa_known_exploited", "is_kev", "kev"],
    "base_score"    : ["base_score", "cvss_base_score", "baseScore"],
    "attack_vector" : ["attack_vector", "attackVector", "av"],
    "attack_complexity": ["attack_complexity", "attackComplexity", "ac"],
}


def _resolve_column(df: pd.DataFrame, canonical: str) -> str:
    """
    Return the actual column name in df that matches canonical or any alias.
    Raises ValueError with a clear message if nothing matches.
    """
    candidates = COLUMN_ALIASES.get(canonical, [canonical])
    for candidate in candidates:
        if candidate in df.columns:
            return candidate
    raise ValueError(
        f"Column '{canonical}' not found in CSV.\n"
        f"  Tried aliases: {candidates}\n"
        f"  Available columns: {list(df.columns)}\n"
        f"  Rename your CSV column to '{canonical}' and re-run."
    )


def _infer_owasp(name: str, desc: str) -> str:
    text = (name + " " + desc).lower()
    for kw, cat in CWE_OWASP_RULES:
        if kw in text:
            return cat
    return "Other"


# ---------------------------------------------------------------------------
# 1. CWE details — MITRE official CSV
# ---------------------------------------------------------------------------

def _build_cwe_lookup_fallback() -> dict:
    entries = [
        ("CWE-89",    "SQL Injection",                        "base"),
        ("CWE-79",    "Cross-site Scripting",                 "base"),
        ("CWE-78",    "OS Command Injection",                 "base"),
        ("CWE-22",    "Path Traversal",                       "base"),
        ("CWE-94",    "Code Injection",                       "base"),
        ("CWE-611",   "XML External Entity",                  "base"),
        ("CWE-918",   "Server-Side Request Forgery",          "base"),
        ("CWE-352",   "Cross-Site Request Forgery",           "base"),
        ("CWE-284",   "Broken Access Control",                "class"),
        ("CWE-285",   "Improper Authorization",               "base"),
        ("CWE-639",   "Insecure Direct Object Reference",     "variant"),
        ("CWE-287",   "Improper Authentication",              "class"),
        ("CWE-306",   "Missing Authentication",               "base"),
        ("CWE-798",   "Hardcoded Credentials",                "base"),
        ("CWE-312",   "Cleartext Storage of Sensitive Info",  "base"),
        ("CWE-319",   "Cleartext Transmission",               "base"),
        ("CWE-502",   "Deserialization of Untrusted Data",    "base"),
        ("CWE-400",   "Uncontrolled Resource Consumption",    "class"),
        ("CWE-434",   "Unrestricted File Upload",             "base"),
        ("CWE-601",   "Open Redirect",                        "base"),
        ("CWE-200",   "Exposure of Sensitive Information",    "class"),
        ("CWE-209",   "Error Message Info Exposure",          "variant"),
        ("CWE-732",   "Incorrect Permission Assignment",      "base"),
        ("CWE-1021",  "Improper Frame Restrictions",          "base"),
        ("CWE-295",   "Improper Certificate Validation",      "base"),
        ("CWE-326",   "Inadequate Encryption Strength",       "base"),
        ("CWE-327",   "Broken Crypto Algorithm",              "class"),
        ("CWE-330",   "Insufficient Random Values",           "class"),
        ("CWE-noinfo","Unknown",                              "class"),
        ("CWE-Other", "Other",                                "class"),
    ]
    lookup = {}
    for cwe_key, name, abstr in entries:
        owasp_cat = _infer_owasp(name, "")
        lookup[cwe_key] = {
            "owasp_category":    owasp_cat,
            "owasp_encoded":     OWASP_CATEGORY_MAP_NUMERIC.get(owasp_cat, 0),
            "abstraction_level": CWE_ABSTRACTION_MAP.get(abstr, 1),
            "cwe_name":          name,
        }
    print(f"[CWE] fallback: {len(lookup)} hardcoded entries")
    return lookup


def build_cwe_lookup() -> dict:
    """
    Downloads MITRE CWE CSV — has Name, Description, Weakness Abstraction.
    Falls back to hardcoded table if unreachable.
    """
    url = "https://cwe.mitre.org/data/csv/699.csv.zip"
    print(f"[CWE] downloading MITRE CSV ...")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            with zf.open(zf.namelist()[0]) as f:
                df = pd.read_csv(f, low_memory=False)

        lookup  = {}
        skipped = 0
        for _, row in df.iterrows():
            raw_id = str(row.get("CWE-ID") or "").strip()
            if not raw_id or raw_id.lower() == "nan":
                skipped += 1
                continue
            cwe_key   = f"CWE-{raw_id}" if not raw_id.startswith("CWE-") else raw_id
            name      = str(row.get("Name")                 or "").strip()
            desc      = str(row.get("Description")          or "").strip()
            abstr     = str(row.get("Weakness Abstraction") or "").strip().lower()
            owasp_cat = _infer_owasp(name, desc)
            lookup[cwe_key] = {
                "owasp_category":    owasp_cat,
                "owasp_encoded":     OWASP_CATEGORY_MAP_NUMERIC.get(owasp_cat, 0),
                "abstraction_level": CWE_ABSTRACTION_MAP.get(abstr, 1),
                "cwe_name":          name,
            }
        print(f"[CWE] {len(lookup):,} entries  |  {skipped} skipped")
        return lookup

    except Exception as e:
        print(f"[CWE] download failed ({e}) — using fallback")
        return _build_cwe_lookup_fallback()


# ---------------------------------------------------------------------------
# 2. CVE→CWE mapping — stasvinokur HuggingFace dataset
# ---------------------------------------------------------------------------

def build_cve_cwe_map() -> dict:
    """
    Returns { "CVE-XXXX-XXXXX": "CWE-NNN" }
    Used to stamp cwe_id onto CVE records that don't have one in Kaggle CSV.
    """
    print("[CVE→CWE] loading stasvinokur dataset ...")
    try:
        ds = load_dataset(
            "stasvinokur/cve-and-cwe-dataset-1999-2025",
            split="train",
        )
    except Exception as e:
        print(f"[CVE→CWE] failed ({e}) — no CVE→CWE mapping available")
        return {}

    mapping = {}
    skipped = 0
    for row in ds:
        cve_raw = str(
            row.get("cve_id") or row.get("CVE-ID") or
            row.get("cveId")  or ""
        ).strip().upper()
        cwe_raw = str(
            row.get("cwe_id") or row.get("CWE-ID") or
            row.get("cweId")  or ""
        ).strip().upper()

        if not cve_raw or not cwe_raw:
            skipped += 1
            continue

        if not cve_raw.startswith("CVE-"):
            cve_raw = f"CVE-{cve_raw}"
        if not cwe_raw.startswith("CWE-"):
            cwe_raw = f"CWE-{cwe_raw}"

        if cve_raw not in mapping:
            mapping[cve_raw] = cwe_raw

    print(f"[CVE→CWE] {len(mapping):,} mappings  |  {skipped} skipped")
    return mapping


# ---------------------------------------------------------------------------
# 3. CVE lookup — Kaggle CSV (local file, 155k entries)
# ---------------------------------------------------------------------------

def build_cve_lookups(csv_path: str,
                      cwe_lookup: dict,
                      cve_cwe_map: dict) -> tuple[dict, dict, dict]:
    """
    Reads the Kaggle CSV and produces three dicts:
      nvd_lookup  — full CVE record
      epss_lookup — fast-path: epss + percentile
      kev_lookup  — fast-path: is_kev + kev_ransomware
    """
    print(f"[CVE] loading Kaggle CSV: {csv_path} ...")
    df = pd.read_csv(csv_path, low_memory=False)
    print(f"[CVE] shape: {df.shape}")
    print(f"[CVE] columns: {list(df.columns)}")

    # FIX #6: Validate required columns exist before processing.
    # Raises ValueError immediately with the offending column name and
    # available alternatives — no silent all-zero enrichment.
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        # Try to resolve via aliases before failing hard
        unresolvable = []
        for col in missing:
            try:
                resolved = _resolve_column(df, col)
                print(f"[CVE] column alias resolved: '{col}' → '{resolved}'")
                df = df.rename(columns={resolved: col})
            except ValueError as e:
                unresolvable.append(str(e))
        if unresolvable:
            raise ValueError(
                "Cannot proceed — unresolvable columns:\n" +
                "\n".join(unresolvable)
            )

    # FIX #6: Resolve optional columns with aliases before use
    epss_perc_col = None
    for alias in COLUMN_ALIASES["epss_perc"]:
        if alias in df.columns:
            epss_perc_col = alias
            break
    if epss_perc_col is None:
        print("[CVE] WARNING: epss_perc column not found — epss_percentile will be 0.0")
        df["epss_perc"] = 0.0
    elif epss_perc_col != "epss_perc":
        df = df.rename(columns={epss_perc_col: "epss_perc"})

    attack_complexity_col = None
    for alias in COLUMN_ALIASES["attack_complexity"]:
        if alias in df.columns:
            attack_complexity_col = alias
            break
    if attack_complexity_col is None:
        print("[CVE] WARNING: attack_complexity column not found — defaulting to 0")
        df["attack_complexity"] = "UNKNOWN"
    elif attack_complexity_col != "attack_complexity":
        df = df.rename(columns={attack_complexity_col: "attack_complexity"})

    # ── Normalise CVE IDs ─────────────────────────────────────────────────
    df["cve_id"] = df["cve_id"].astype(str).str.strip().str.upper()

    # ── Deduplicate: keep highest base_score per CVE ──────────────────────
    df["base_score"] = pd.to_numeric(df["base_score"], errors="coerce").fillna(0.0)
    df = (df.sort_values("base_score", ascending=False)
            .drop_duplicates(subset="cve_id", keep="first")
            .reset_index(drop=True))
    print(f"[CVE] after dedup: {len(df):,} unique CVEs")

    # ── Fill missing EPSS with 0 ──────────────────────────────────────────
    df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce").fillna(0.0)
    df["epss_perc"]  = pd.to_numeric(df["epss_perc"],  errors="coerce").fillna(0.0)

    # ── Normalise cisa_kev (bool / str / int) ─────────────────────────────
    kev_series = df["cisa_kev"]
    if kev_series.dtype == bool:
        df["_is_kev"] = kev_series.astype(int)
    else:
        df["_is_kev"] = (
            kev_series.astype(str).str.lower()
            .map({"true": 1, "1": 1, "yes": 1,
                  "false": 0, "0": 0, "no": 0})
            .fillna(0).astype(int)
        )

    # ── Normalise attack_vector ───────────────────────────────────────────
    df["_attack_vector"] = (
        df["attack_vector"].astype(str).str.upper()
        .map(ATTACK_VECTOR_MAP)
        .fillna(0).astype(int)
    )

    # ── Normalise attack_complexity ───────────────────────────────────────
    df["_attack_complexity"] = (
        df["attack_complexity"].astype(str).str.upper()
        .map(ATTACK_COMPLEXITY_MAP)
        .fillna(0).astype(int)
    )

    # ── Build lookup dicts ────────────────────────────────────────────────
    nvd_lookup  = {}
    epss_lookup = {}
    kev_lookup  = {}

    for _, row in df.iterrows():
        cve       = row["cve_id"]
        epss_val  = float(row["epss_score"]               or 0.0)
        epssp_val = float(row["epss_perc"]                or 0.0)
        expl_val  = float(row.get("exploitability_score") or 0.0)
        imp_val   = float(row.get("impact_score")         or 0.0)
        is_kev    = int(row["_is_kev"])

        cwe_id   = cve_cwe_map.get(cve, "")
        cwe_info = cwe_lookup.get(cwe_id, {})

        nvd_lookup[cve] = {
            "cvss":                 float(row["base_score"] or 0.0),
            "exploitability_score": expl_val,
            "impact_score":         imp_val,
            "epss":                 epss_val,
            "epss_percentile":      epssp_val,
            "is_kev":               is_kev,
            "kev_ransomware":       0,    # patched in step 4
            "attack_vector":        int(row["_attack_vector"]),
            "attack_complexity":    int(row["_attack_complexity"]),
            "cwe_id":               cwe_id,
            "owasp_encoded":        cwe_info.get("owasp_encoded",     0),
            "owasp_category":       cwe_info.get("owasp_category",    "Other"),
            "abstraction_level":    cwe_info.get("abstraction_level", 1),
        }

        epss_lookup[cve] = {
            "epss":       epss_val,
            "percentile": epssp_val,
        }

        kev_lookup[cve] = {
            "is_kev":         is_kev,
            "kev_ransomware": 0,
        }

    kev_count = sum(1 for v in kev_lookup.values() if v["is_kev"])
    cwe_hit   = sum(1 for v in nvd_lookup.values() if v["owasp_encoded"] != 0)
    print(f"[CVE] {len(nvd_lookup):,} entries  |  "
          f"KEV={kev_count}  |  CWE-resolved={cwe_hit:,}")

    return nvd_lookup, epss_lookup, kev_lookup


# ---------------------------------------------------------------------------
# 4. KEV ransomware flag — CISA JSON
# ---------------------------------------------------------------------------

def patch_kev_ransomware(kev_lookup: dict, nvd_lookup: dict) -> None:
    """
    Kaggle CSV has cisa_kev but not the ransomware flag.
    CISA JSON has both — patch it in after the fact.
    Mutates kev_lookup and nvd_lookup in place.

    FIX #4: On network failure, logs an explicit WARNING instead of silently
    leaving kev_ransomware=0. This makes it clear in CI logs that the
    ransomware bonus is disabled rather than appearing to run correctly.
    """
    print("[KEV] patching ransomware flag from cisa.gov ...")
    try:
        url  = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
        data = requests.get(url, timeout=30).json()
        patched = 0
        for entry in data.get("vulnerabilities", []):
            cve    = str(entry.get("cveID") or "").strip().upper()
            ransom = 1 if "ransomware" in str(
                entry.get("notes", "")).lower() else 0
            if cve in kev_lookup:
                kev_lookup[cve]["kev_ransomware"] = ransom
            if cve in nvd_lookup:
                nvd_lookup[cve]["kev_ransomware"] = ransom
                patched += 1
        print(f"[KEV] ransomware flag patched for {patched:,} CVEs")
    except Exception as e:
        # FIX #4: Explicit warning — kev_ransomware bonus will not fire
        print(f"[KEV] WARNING: CISA patch failed ({e})")
        print(f"[KEV] kev_ransomware=0 for all entries — "
              f"+1.0 ransomware bonus disabled in scoring")
        print(f"[KEV] Re-run build_lookups.py with network access to enable it")


# ---------------------------------------------------------------------------
# Master build
# ---------------------------------------------------------------------------

def build_and_save(
    csv_path:    str = "kaggle.csv",
    output_path: str = "lookups.pkl",
):
    # 1. CWE details from MITRE
    cwe_lookup = build_cwe_lookup()

    # 2. CVE→CWE mapping from stasvinokur
    cve_cwe_map = build_cve_cwe_map()

    # 3. CVE data from Kaggle CSV — joined with cwe_lookup via cve_cwe_map
    nvd_lookup, epss_lookup, kev_lookup = build_cve_lookups(
        csv_path, cwe_lookup, cve_cwe_map
    )

    # 4. Patch ransomware flag from CISA
    patch_kev_ransomware(kev_lookup, nvd_lookup)

    lookups = {
        "nvd":  nvd_lookup,
        "epss": epss_lookup,
        "kev":  kev_lookup,
        "cwe":  cwe_lookup,
    }

    with open(output_path, "wb") as f:
        pickle.dump(lookups, f, protocol=5)

    sizes = {k: len(v) for k, v in lookups.items()}
    print(f"\n[OK] saved → {output_path}")
    print(f"     nvd={sizes['nvd']:,}  epss={sizes['epss']:,}  "
          f"kev={sizes['kev']:,}  cwe={sizes['cwe']:,}")


if __name__ == "__main__":
    csv = sys.argv[1] if len(sys.argv) > 1 else "kaggle.csv"
    out = sys.argv[2] if len(sys.argv) > 2 else "lookups.pkl"
    build_and_save(csv, out)
