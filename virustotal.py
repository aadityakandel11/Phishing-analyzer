import requests
import time
from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_URL, RATE_LIMIT_DELAY

def check_url(url):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    payload = {"url": url}
    response = requests.post(
        f"{VIRUSTOTAL_URL}/urls",
        headers=headers,
        data=payload
    )

    if response.status_code != 200:
        return {"error": f"Failed to submit URL: {response.status_code}", "url": url, "verdict": "UNKNOWN"}

    scan_id = response.json()["data"]["id"]
    time.sleep(RATE_LIMIT_DELAY)

    result = requests.get(
        f"{VIRUSTOTAL_URL}/analyses/{scan_id}",
        headers=headers
    )

    if result.status_code != 200:
        return {"error": f"Failed to get results: {result.status_code}", "url": url, "verdict": "UNKNOWN"}

    data = result.json()

    if "data" not in data:
        return {"error": "Unexpected response", "url": url, "verdict": "UNKNOWN"}

    stats = data["data"]["attributes"]["stats"]

    if not isinstance(stats, dict):
        return {"error": "Could not parse stats", "url": url, "verdict": "UNKNOWN"}

    return {
        "url": url,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "clean": stats["undetected"],
        "verdict": get_verdict(stats)
    }

def check_ip(ip):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.get(
        f"{VIRUSTOTAL_URL}/ip_addresses/{ip}",
        headers=headers
    )

    if response.status_code != 200:
        return {"error": f"Failed to check IP: {response.status_code}", "ip": ip, "verdict": "UNKNOWN"}

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]

    return {
        "ip": ip,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "clean": stats["undetected"],
        "verdict": get_verdict(stats)
    }

def get_verdict(stats):
    if stats["malicious"] >= 3:
        return "MALICIOUS"
    elif stats["suspicious"] >= 1:
        return "SUSPICIOUS"
    else:
        return "CLEAN"