# scanner.py

from dast import wait_for_zap, start_session, spider, active_scan, get_alerts, normalize_zap
from sast import fetch_sonar_issues, normalize_sonar

def full_scan(target_url, project_key):

    # DAST
    wait_for_zap()
    start_session()
    spider(target_url)
    active_scan(target_url)

    zap_alerts = get_alerts()
    normalized_dast = [normalize_zap(a) for a in zap_alerts]

    # SAST
    sonar_issues = fetch_sonar_issues(project_key)
    normalized_sast = [normalize_sonar(i) for i in sonar_issues]

    combined = normalized_sast + normalized_dast

    return combined