import subprocess
import time
import requests
from config import SONAR_URL, SONAR_TOKEN


def run_sonar_scan(repo_url, project_key):

    print("Running SAST inside Docker scanner container...")

    cmd = [
        "docker", "run", "--rm",
        "sonarsource/sonar-scanner-cli",
        "bash", "-c",
        f"""
        git clone {repo_url} repo &&
        cd repo &&
        sonar-scanner \
          -Dsonar.projectKey={project_key} \
          -Dsonar.host.url={SONAR_URL} \
          -Dsonar.login={SONAR_TOKEN}
        """
    ]

    subprocess.run(" ".join(cmd), shell=True, check=True)


def wait_for_sonar_processing(project_key):

    print("Waiting for Sonar processing...")

    while True:
        r = requests.get(
            f"{SONAR_URL}/api/ce/component",
            params={"component": project_key},
            auth=(SONAR_TOKEN, "")
        )

        data = r.json()

        if "current" in data:
            status = data["current"]["status"]
            if status == "SUCCESS":
                break

        time.sleep(3)


def fetch_sonar_issues(project_key):

    r = requests.get(
        f"{SONAR_URL}/api/issues/search",
        params={"componentKeys": project_key},
        auth=(SONAR_TOKEN, "")
    )

    return r.json().get("issues", [])


def normalize_sonar(issue):
    return {
        "source": "SAST",
        "name": issue["message"],
        "severity": issue["severity"],
        "file": issue.get("component"),
        "line": issue.get("line"),
        "description": issue.get("message")
    }