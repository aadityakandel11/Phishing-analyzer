import requests
import time
from config import URLSCAN_API_KEY, URLSCAN_URL

def scan_url(url):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "url": url,
        "visibility": "public"
    }

    try:
        response = requests.post(
            f"{URLSCAN_URL}/scan/",
            headers=headers,
            json=payload
        )
        print("Resp", response.json())

        if response.status_code == 400:
            print("ERROR!!!",response.json())
            return {"error": f"URLScan rejected URL (400)", "url": url, "verdict": "UNKNOWN"}

        if response.status_code == 429:
            print("  URLScan rate limit hit - waiting 60 seconds...")
            time.sleep(60)
            return scan_url(url)

        if response.status_code != 200:
            return {"error": f"Failed to submit: {response.status_code}", "url": url, "verdict": "UNKNOWN"}

        scan_uuid = response.json().get("uuid")
        if not scan_uuid:
            return {"error": "No scan ID returned", "url": url, "verdict": "UNKNOWN"}

        print(f"  Waiting 30 seconds for URLScan to finish...")
        time.sleep(30)

        for attempt in range(3):
            result = requests.get(
                f"{URLSCAN_URL}/result/{scan_uuid}/",
                headers=headers
            )

            if result.status_code == 200:
                data = result.json()
                return {
                    "url": url,
                    "screenshot": data.get("task", {}).get("screenshotURL", "N/A"),
                    "malicious": data.get("verdicts", {}).get("overall", {}).get("malicious", False),
                    "score": data.get("verdicts", {}).get("overall", {}).get("score", 0),
                    "categories": data.get("verdicts", {}).get("overall", {}).get("categories", []),
                    "verdict": "MALICIOUS" if data.get("verdicts", {}).get("overall", {}).get("malicious") else "CLEAN"
                }

            elif result.status_code == 404:
                print(f"  Result not ready yet, waiting 15 more seconds... (attempt {attempt + 1}/3)")
                time.sleep(15)

            else:
                return {"error": f"Failed to get result: {result.status_code}", "url": url, "verdict": "UNKNOWN"}

        return {"error": "Scan timed out after 3 attempts", "url": url, "verdict": "UNKNOWN"}

    except Exception as e:
        return {"error": f"Exception: {str(e)}", "url": url, "verdict": "UNKNOWN"}