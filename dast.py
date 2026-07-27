# dast.py

import requests
import time
from config import ZAP_URL

def wait_for_zap():
    while True:
        try:
            r = requests.get(f"{ZAP_URL}/JSON/core/view/version/")
            if r.status_code == 200:
                break
        except:
            pass
        time.sleep(3)

def start_session():
    requests.get(f"{ZAP_URL}/JSON/core/action/newSession/")

def spider(target):
    r = requests.get(
        f"{ZAP_URL}/JSON/spider/action/scan/?url={target}"
    )
    scan_id = r.json()['scan']

    while True:
        status = requests.get(
            f"{ZAP_URL}/JSON/spider/view/status/?scanId={scan_id}"
        ).json()['status']

        if int(status) >= 100:
            break

        time.sleep(2)

def active_scan(target):
    r = requests.get(
        f"{ZAP_URL}/JSON/ascan/action/scan/?url={target}"
    )
    scan_id = r.json()['scan']

    while True:
        try:
            status = requests.get(
                f"{ZAP_URL}/JSON/ascan/view/status/?scanId={scan_id}"
            ).json()['status']

            if int(status) >= 100:
                break
        except:
            time.sleep(5)
            continue

        time.sleep(5)

def get_alerts():
    alerts = requests.get(
        f"{ZAP_URL}/JSON/core/view/alerts/"
    ).json()['alerts']

    return alerts

def normalize_zap(alert):
    return {
        "source": "DAST",
        "name": alert["alert"],
        "severity": alert["risk"],
        "url": alert.get("url"),
        "description": alert.get("description")
    }