import os
import time
import json
import subprocess
import requests

from pentest import test_sqli, test_xss, run_nuclei, run_sqlmap, run_metasploit
from cvc import prioritize
from genai import check_llm_connection, generate_patch, load_code_context, judge_patch

# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
ZAP          = "http://zap:8080"
SONAR_URL    = "http://sonarqube:9000"
PROJECT_KEY  = "vulnity"
SONAR_TOKEN  = os.getenv("SONAR_TOKEN", "sqa_4c54184b75d92f9d4e3d7df4550984790bf6e59b")
SONAR_AUTH   = (SONAR_TOKEN, "")
LOOKUPS_PATH = "lookups.pkl"
JUDGE_MAX_RETRIES = int(os.getenv("JUDGE_MAX_RETRIES", "1"))


# ---------------------------------------------------------------------------
# REPO MANAGEMENT
# ---------------------------------------------------------------------------

def ensure_repo(REPO_URL):
    marker = "/app/shared/.repo_url"

    if os.path.exists("/app/shared/repo") and os.path.exists(marker):
        with open(marker) as f:
            cached_url = f.read().strip()
        if cached_url == REPO_URL:
            print(f"[Repo] Already cloned: {REPO_URL} — skipping.")
            _ensure_lockfile()   # ← always ensure lockfile exists
            return
        else:
            print(f"[Repo] URL changed, re-cloning...")
            subprocess.run("rm -rf /app/shared/repo", shell=True)

    print(f"[Repo] Cloning {REPO_URL}...")
    clone_url = REPO_URL if REPO_URL.endswith(".git") else f"{REPO_URL}.git"
    subprocess.run(
        f"git clone --depth=1 {clone_url} /app/shared/repo",
        shell=True, check=True
    )
    with open(marker, "w") as f:
        f.write(REPO_URL)
    _ensure_lockfile()   # ← copy lockfile after fresh clone
    print("[Repo] Clone complete.")

def _ensure_lockfile():
    """Copy backup lockfile to root so Trivy can find it."""
    lockfile = "/app/shared/repo/package-lock.json"
    yarn_lock = "/app/shared/repo/yarn.lock"
    backup    = "/app/shared/repo/ftp/package-lock.json.bak"

    if os.path.exists(lockfile) or os.path.exists(yarn_lock):
        return  # already there

    if os.path.exists(backup):
        subprocess.run(f"cp {backup} {lockfile}", shell=True)
        print("[Repo] Copied package-lock.json.bak to repo root for Trivy.")
    else:
        print("[Repo] No lockfile found — Trivy SCA may return 0 findings.")




# ---------------------------------------------------------------------------
# ZAP (DAST)
# ---------------------------------------------------------------------------

def wait_for_zap():
    print("Waiting for ZAP to be ready...")
    while True:
        try:
            r = requests.get(f"{ZAP}/JSON/core/view/version/", timeout=5)
            if r.status_code == 200:
                print("ZAP is ready")
                break
        except Exception:
            pass
        time.sleep(3)

def disable_heavy_scan_rules():
    """
    Disable scan rules that require headless Firefox (DOM XSS).
    These cause TimeoutException and OOM on WSL2 with limited memory.
    Rule 40026 = DOM XSS Active Scan Rule
    """
    try:
        # Disable DOM XSS rule (requires Firefox, crashes on WSL2)
        requests.get(
            f"{ZAP}/JSON/ascan/action/disableScanners/"
            f"?ids=40026",
            timeout=5
        )
        print("[ZAP] Disabled DOM XSS scanner (rule 40026)")

        # Also disable other browser-dependent rules
        requests.get(
            f"{ZAP}/JSON/ascan/action/disableScanners/"
            f"?ids=40026,40012,40014,40016,40017",
            timeout=5
        )
        print("[ZAP] Disabled browser-dependent scan rules")
    except Exception as e:
        print(f"[ZAP] Could not disable rules: {e}")


def start_session(TARGET):
    requests.get(f"{ZAP}/JSON/core/action/newSession/")
    print("New ZAP session started")
    print(f"Seeding {TARGET} into ZAP...")
    try:
        requests.get(TARGET,
                     proxies={"http": ZAP, "https": ZAP},
                     timeout=10)
    except Exception:
        pass


def spider(TARGET):
    print("Starting spider...")
    # Use IP so ZAP records it under the IP-based URL
    ip = get_juiceshop_ip()
    scan_target = TARGET.replace("juice-shop", ip) if ip else TARGET
    print(f"[ZAP] Spidering: {scan_target}")

    r = requests.get(
        f"{ZAP}/JSON/spider/action/scan/?url={scan_target}&maxChildren=10"
    )
    scan_id = r.json().get("scan", "0")

    while True:
        try:
            status = requests.get(
                f"{ZAP}/JSON/spider/view/status/?scanId={scan_id}",
                timeout=10
            ).json()["status"]
            print(f"Spider progress: {status}%")
            if int(status) >= 100:
                break
        except Exception as e:
            print(f"Spider error: {e}")
            break
        time.sleep(5)
    print("Spider completed.")
    return scan_target


def get_juiceshop_ip():
    """Get the actual IP of juice-shop container for ZAP direct scans."""
    try:
        import socket
        ip = socket.gethostbyname("juice-shop")
        print(f"[ZAP] juice-shop IP: {ip}")
        return ip
    except Exception as e:
        print(f"[ZAP] Could not resolve juice-shop: {e}")
        return None


def active_scan(scan_target):
    print("Starting active scan...")
    print(f"[ZAP] Active scanning: {scan_target}")
    try:
        r = requests.get(
            f"{ZAP}/JSON/ascan/action/scan/?url={scan_target}",
            timeout=30
        )
        data = r.json()
    except Exception as e:
        print(f"[ZAP] Active scan failed to start: {e}")
        return

    if "scan" not in data:
        print(f"ERROR: ZAP refused active scan. Response: {data}")
        return

    scan_id = data["scan"]
    while True:
        try:
            status = requests.get(
                f"{ZAP}/JSON/ascan/view/status/?scanId={scan_id}",
                timeout=30
            ).json()["status"]
            print(f"Active scan progress: {status}%")
            if int(status) >= 100:
                break
        except Exception as e:
            print(f"[ZAP] Scan interrupted: {e} — continuing pipeline...")
            break
        time.sleep(5)
    print("Active scan completed.")


def get_alerts():
    try:
        alerts = requests.get(
            f"{ZAP}/JSON/core/view/alerts/", timeout=60
        ).json().get("alerts", [])
    except Exception as e:
        print(f"[ZAP] Failed to fetch alerts: {e}")
        return []

    print(f"\n[ZAP] Found {len(alerts)} alerts")
    normalized = []
    for a in alerts:
        normalized.append({
            "tool"       : "zap",
            "source"     : "DAST",
            "name"       : a.get("alert", "Unknown Alert"),
            "severity"   : _map_zap_risk(a.get("risk", "Low")),
            "url"        : a.get("url", ""),
            "endpoint"   : a.get("url", ""),
            "description": a.get("description", ""),
            "cwe"        : f"CWE-{a['cweid']}" if a.get("cweid") else "",
        })
    return normalized


def _map_zap_risk(zap_risk: str) -> str:
    return {
        "High"         : "HIGH",
        "Medium"       : "MEDIUM",
        "Low"          : "LOW",
        "Informational": "INFO",
    }.get(zap_risk, "LOW")


# ---------------------------------------------------------------------------
# SONARQUBE (SAST)
# ---------------------------------------------------------------------------

def wait_for_sonarqube_ready(timeout=180):
    print("Waiting for SonarQube to be ready...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(
                f"{SONAR_URL}/api/system/status",
                auth=SONAR_AUTH,
                timeout=5
            )
            if r.status_code == 200:
                status = r.json().get("status", "")
                print(f"SonarQube status: {status}")
                if status == "UP":
                    print("SonarQube is ready.")
                    return
        except Exception:
            pass
        print("SonarQube not ready yet, retrying in 5s...")
        time.sleep(5)
    raise TimeoutError("SonarQube did not become ready in time.")


def run_sonar_scan(REPO_URL):
    print("\nRunning SonarQube scan...\n")
    ensure_repo(REPO_URL)

    scan_cmd = (
        "docker run --rm "
        "--network orchestrator_default "
        f"-e SONAR_HOST_URL={SONAR_URL} "
        "-v orchestrator_shared_workspace:/usr/src "
        "sonarsource/sonar-scanner-cli "
        f"-Dsonar.projectKey={PROJECT_KEY} "
        f"-Dsonar.projectName={PROJECT_KEY} "
        "-Dsonar.sources=/usr/src/repo "
        f"-Dsonar.login={SONAR_TOKEN} "
        "-Dsonar.exclusions=target-app/** "
        "-Dsonar.scm.disabled=true"
    )

    try:
        result = subprocess.run(
            scan_cmd, shell=True, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print("=== SONAR SCANNER STDOUT ===")
        print(e.stdout)
        print("=== SONAR SCANNER STDERR ===")
        print(e.stderr)
        raise RuntimeError(
            f"Sonar scan failed (exit {e.returncode}). See output above."
        ) from e


def wait_for_sonar():
    print("Waiting for SonarQube processing...")
    for _ in range(40):
        try:
            r = requests.get(
                f"{SONAR_URL}/api/ce/component",
                params={"component": PROJECT_KEY},
                auth=SONAR_AUTH,
                timeout=10
            )
            if r.status_code != 200:
                print(f"API Error {r.status_code}: {r.text}")
                time.sleep(3)
                continue

            data = r.json()
            if "current" in data and "status" in data["current"]:
                status = data["current"]["status"]
                print(f"SonarQube task status: {status}")
                if status == "SUCCESS":
                    break
                elif status in ("FAILED", "CANCELED"):
                    print("SonarQube processing failed or canceled.")
                    break
        except Exception as e:
            print(f"[Sonar] wait error: {e}")
        time.sleep(3)
    print("SonarQube analysis complete.")


def fetch_sonar_issues():
    print("\nFetching SAST results from SonarQube...")
    url      = f"{SONAR_URL}/api/issues/search?componentKeys={PROJECT_KEY}&ps=500"
    response = requests.get(url, auth=SONAR_AUTH)

    if response.status_code != 200:
        print(f"Error fetching issues: {response.status_code}")
        return []

    issues = response.json().get("issues", [])
    print(f"Found {len(issues)} SAST issues")
    return issues


def load_sonar_issues_from_file(path=None):
    """Fallback: load Sonar issues from a saved JSON export."""
    candidate_paths = []
    if path:
        candidate_paths.append(path)
    candidate_paths.extend([
        "/app/shared/sonar_results.json",
        "sonar_results.json",
    ])

    chosen_path = next((p for p in candidate_paths if os.path.exists(p)), None)
    if not chosen_path:
        print("[SAST] sonar_results.json not found; skipping SAST stage")
        return []

    try:
        with open(chosen_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[SAST] failed to read '{chosen_path}': {e}")
        return []

    if isinstance(data, dict):
        issues = data.get("issues", [])
    elif isinstance(data, list):
        issues = data
    else:
        print(f"[SAST] unsupported format in '{chosen_path}'")
        return []

    print(f"[SAST] loaded {len(issues)} Sonar issues from {chosen_path}")
    return issues


def normalize_sonar(issue):
    return {
        "tool"       : "sonarqube",
        "source"     : "SAST",
        "name"       : issue.get("message", "Unknown Issue"),
        "severity"   : issue.get("severity", "INFO"),
        "file"       : issue.get("component", ""),
        "line"       : issue.get("line"),
        "description": issue.get("message", ""),
        "cwe"        : issue.get("cwe", ""),
    }


# ---------------------------------------------------------------------------
# TRIVY (SCA)
# ---------------------------------------------------------------------------

def run_trivy_sca(REPO_URL):
    print("\nRunning Trivy SCA scan...\n")
    ensure_repo(REPO_URL)
    _ensure_lockfile() 

    cmd = [
        "docker", "run", "--rm",
        "--network", "orchestrator_default",
        "-v", "orchestrator_shared_workspace:/workspace",
        "aquasec/trivy:latest",
        "fs",
        "--scanners", "vuln",
        "--format", "json",
        "-o", "/workspace/trivy_results.json",
        "/workspace/repo/package-lock.json"   # ← scan package.json directly
    ]
    process = subprocess.run(cmd, capture_output=True, text=True)
    if process.returncode != 0:
        print("Trivy scan failed.")
        print(process.stderr)
    else:
        print("[Trivy] Scan completed successfully.")


def normalize_trivy():
    file_path = "/app/shared/trivy_results.json"
    if not os.path.exists(file_path):
        return []

    with open(file_path) as f:
        data = json.load(f)

    results = []
    for target in data.get("Results", []):
        for vuln in (target.get("Vulnerabilities") or []):
            pkg_name  = vuln.get("PkgName", "unknown-package")
            installed = vuln.get("InstalledVersion", "unknown-version")
            vuln_id   = vuln.get("VulnerabilityID", "unknown-id")
            title     = (vuln.get("Title") or
                         vuln.get("Description") or vuln_id)
            results.append({
                "tool"       : "trivy",
                "source"     : "SCA",
                "name"       : f"{vuln_id} in {pkg_name}",
                "severity"   : vuln.get("Severity", "LOW"),
                "file"       : target.get("Target"),
                "line"       : None,
                "description": f"{title} (installed: {installed})",
                "cve"        : vuln_id if vuln_id.startswith("CVE-") else "",
            })
    return results


# ---------------------------------------------------------------------------
# NUCLEI
# ---------------------------------------------------------------------------

def normalize_nuclei():
    file_path = "/app/shared/nuclei_results.json"
    if not os.path.exists(file_path):
        return []

    results = []
    with open(file_path) as f:
        for line in f:
            try:
                issue = json.loads(line)
                results.append({
                    "tool"    : "nuclei",
                    "source"  : "DAST",
                    "name"    : issue.get("template-id", "unknown"),
                    "severity": issue.get("info", {}).get(
                                    "severity", "low").upper(),
                    "url"     : issue.get("matched-at", ""),
                    "endpoint": issue.get("matched-at", ""),
                })
            except json.JSONDecodeError:
                continue
    return results


# ---------------------------------------------------------------------------
# MAIN ORCHESTRATOR
# ---------------------------------------------------------------------------

def run_all(TARGET, REPO_URL):
    os.makedirs("/app/shared", exist_ok=True)

    # ── SAST ────────────────────────────────────────────────────────────
    try:
        wait_for_sonarqube_ready()
        run_sonar_scan(REPO_URL)
        wait_for_sonar()
        sast_issues = fetch_sonar_issues()
    except Exception as e:
        print(f"[SAST] live SonarQube stage failed: {e}")
        print("[SAST] falling back to sonar_results.json if present...")
        sast_issues = load_sonar_issues_from_file()

    normalized_sast = [normalize_sonar(i) for i in sast_issues]
    print(f"[SAST] {len(normalized_sast)} findings normalized")

    # ── DAST ────────────────────────────────────────────────────────────
    try:
        wait_for_zap()
        disable_heavy_scan_rules()
        start_session(TARGET)
        scan_target = spider(TARGET)      # ← capture returned URL
        active_scan(scan_target) 
        normalized_zap = get_alerts()
    except Exception as e:
        print(f"[ZAP] DAST stage failed: {e} — continuing...")
        normalized_zap = []
    print(f"[ZAP] {len(normalized_zap)} findings normalized")

    # ── SCA ─────────────────────────────────────────────────────────────
    try:
        run_trivy_sca(REPO_URL)
        normalized_sca = normalize_trivy()
    except Exception as e:
        print(f"[SCA] stage failed: {e} — continuing...")
        normalized_sca = []
    print(f"[SCA] {len(normalized_sca)} findings normalized")

    # ── Pentest ─────────────────────────────────────────────────────────
    normalized_pentest = []

    try:
        sqli_res = test_sqli(TARGET)
        if sqli_res:
            normalized_pentest.extend(sqli_res)
    except Exception as e:
        print(f"[Pentest] SQLi test failed: {e}")

    try:
        xss_res = test_xss(TARGET)
        if xss_res:
            normalized_pentest.extend(xss_res)
    except Exception as e:
        print(f"[Pentest] XSS test failed: {e}")

    try:
        time.sleep(30)
        run_nuclei(TARGET)
        normalized_pentest.extend(normalize_nuclei())
    except Exception as e:
        print(f"[Pentest] Nuclei failed: {e}")

    try:
        time.sleep(15)
        sqlmap_res = run_sqlmap(TARGET)
        if sqlmap_res:
            normalized_pentest.extend(sqlmap_res)
    except Exception as e:
        print(f"[Pentest] SQLMap failed: {e}")

    try:
        msf_res = run_metasploit(TARGET)
        if msf_res:
            normalized_pentest.extend(msf_res)
    except Exception as e:
        print(f"[Pentest] Metasploit failed: {e}")

    print(f"[Pentest] {len(normalized_pentest)} findings normalized")

    # ── Merge ────────────────────────────────────────────────────────────
    all_vulns = []
    for findings in (normalized_sast, normalized_sca,
                     normalized_zap, normalized_pentest):
        if findings:
            all_vulns.extend(findings)

    print(f"[Pipeline] {len(all_vulns)} total findings before deduplication")

    raw_path = "/app/shared/scan_output.json"
    with open(raw_path, "w") as f:
        json.dump(all_vulns, f, indent=2, default=str)
    print(f"[Pipeline] raw findings saved to {raw_path}")

    ranked = prioritize(all_vulns, lookups_path=LOOKUPS_PATH)
    print(f"[Pipeline] {len(ranked)} findings after deduplication and ranking")

    ranked_path = "/app/shared/ranked.json"
    with open(ranked_path, "w") as f:
        json.dump(ranked, f, indent=2, default=str)
    print(f"[Pipeline] ranked findings saved to {ranked_path}")

    # ── LLM Patch Generation ─────────────────────────────────────────────
    llm_ready, llm_status = check_llm_connection()
    print(f"[GenAI] {llm_status}")
    print("\n[GenAI] Generating patch suggestions for top 3 findings...\n")
    final_patches = []

    for vuln in ranked[:3]:
        code_context = None

        if (vuln.get("source") == "SAST"
                and vuln.get("file")
                and vuln.get("line")):
            file_name = (vuln["file"].split(":")[-1]
                         if ":" in vuln["file"]
                         else vuln["file"])
            file_name = file_name.replace("repo/", "", 1)
            file_path = os.path.join("/app/shared/repo", file_name)
            code_context = load_code_context(file_path, vuln["line"])

        if llm_ready:
            fix = generate_patch(vuln, code_context)

            # ── LLM-as-judge: review the generated patch, retry once on fail ──
            verdict = judge_patch(vuln, fix, code_context)
            attempts = 0
            while verdict.get("verdict") == "fail" and attempts < JUDGE_MAX_RETRIES:
                print(f"[Judge] Rejected attempt {attempts + 1} for "
                      f"'{vuln['name']}': {verdict.get('reasoning')}")
                fix = generate_patch(vuln, code_context,
                                     judge_feedback=verdict.get("reasoning"))
                verdict = judge_patch(vuln, fix, code_context)
                attempts += 1

            print(f"[Judge] Final verdict for '{vuln['name']}': "
                  f"{verdict['verdict']} — {verdict['reasoning']}")
        else:
            fix = f" LLM unavailable. {llm_status}"
            verdict = {"verdict": "unverified",
                      "reasoning": "LLM was offline — judge did not run."}

        print(f"Vulnerability : {vuln['name']}")
        print(f"Suggested fix :\n{fix}")
        print("-" * 60)

        final_patches.append({
            "name"          : vuln["name"],
            "patch"         : fix,
            "score"         : vuln.get("priority_score", 0),
            "severity"      : vuln.get("severity", ""),
            "verdict"       : verdict.get("verdict", "unverified"),
            "verdict_reason": verdict.get("reasoning", ""),
        })

    return ranked, final_patches


if __name__ == "__main__":
    pass
    # run_all("http://juice-shop:3000",
    #         "https://github.com/juice-shop/juice-shop")