import sys
import time
from email_parser import parse_email
from virustotal import check_url, check_ip
from urlscan import scan_url
from report import generate_report

def analyze_email(file_path):
    print(f"\n🔍 Analyzing: {file_path}")
    print("Parsing email...")

    email_data = parse_email(file_path)

    print(f"Found {len(email_data['urls'])} URLs")
    print(f"Found {len(email_data['attachments'])} attachments")

    vt_results = []
    urlscan_results = []

    if email_data["urls"]:
        print("\nChecking URLs against VirusTotal...")
        for url in email_data["urls"]:
            print(f"  Checking: {url}")
            result = check_url(url)
            vt_results.append(result)
            time.sleep(2)

        print("\nScanning URLs with URLScan...")
        for url in email_data["urls"]:
            if any(url.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico']):
                print(f"  Skipping image/asset: {url}")
                continue
            print(f"  Scanning: {url}")
            result = scan_url(url)
            urlscan_results.append(result)
            time.sleep(2)

    print("\nGenerating report...")
    report = generate_report(email_data, vt_results, urlscan_results)

    return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_email.eml>")
        print("Example: python3 main.py emails/phish1.eml")
        sys.exit(1)

    file_path = sys.argv[1]

    start_time = time.time()

    report = analyze_email(file_path)

    end_time = time.time()
    elapsed = round(end_time - start_time, 2)

    print(f"✅ Analysis complete in {elapsed} seconds")
    print(f"Overall Verdict: {report['overall_verdict']}")

if __name__ == "__main__":
    main()