import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def generate_report(email_data, vt_results, urlscan_results):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overall_verdict = calculate_overall_verdict(vt_results, urlscan_results)

    report = {
        "timestamp": timestamp,
        "overall_verdict": overall_verdict,
        "email": {
            "subject": email_data["subject"],
            "from": email_data["from"],
            "to": email_data["to"],
            "reply_to": email_data["reply_to"],
            "date": email_data["date"]
        },
        "url_results": vt_results,
        "urlscan_results": urlscan_results,
        "attachments": email_data["attachments"],
        "headers": email_data["headers"]
    }

    print_report(report)
    save_report(report)

    return report

def calculate_overall_verdict(vt_results, urlscan_results):
    for result in vt_results:
        if result.get("verdict") == "MALICIOUS":
            return "MALICIOUS"

    for result in urlscan_results:
        if result.get("verdict") == "MALICIOUS":
            return "MALICIOUS"

    for result in vt_results:
        if result.get("verdict") == "SUSPICIOUS":
            return "SUSPICIOUS"

    return "CLEAN"

def print_report(report):
    verdict_color = {
        "MALICIOUS": Fore.RED,
        "SUSPICIOUS": Fore.YELLOW,
        "CLEAN": Fore.GREEN
    }

    color = verdict_color[report["overall_verdict"]]

    print("\n" + "="*50)
    print("       PHISHING ANALYSIS REPORT")
    print("="*50)
    print(f"Timestamp : {report['timestamp']}")
    print(f"Verdict   : {color}{report['overall_verdict']}{Style.RESET_ALL}")
    print("-"*50)

    print("\n[EMAIL DETAILS]")
    print(f"  Subject  : {report['email']['subject']}")
    print(f"  From     : {report['email']['from']}")
    print(f"  To       : {report['email']['to']}")
    print(f"  Reply-To : {report['email']['reply_to']}")
    print(f"  Date     : {report['email']['date']}")

    print("\n[URL ANALYSIS - VIRUSTOTAL]")
    for result in report["url_results"]:
        if "error" in result:
            print(f"  ✗ Error: {result['error']}")
        else:
            vcolor = verdict_color[result["verdict"]]
            print(f"  ➤ {result['url']}")
            print(f"    Verdict    : {vcolor}{result['verdict']}{Style.RESET_ALL}")
            print(f"    Malicious  : {result['malicious']} engines")
            print(f"    Suspicious : {result['suspicious']} engines")
            print(f"    Clean      : {result['clean']} engines")

    print("\n[URL ANALYSIS - URLSCAN]")
    for result in report["urlscan_results"]:
        if "error" in result:
            print(f"  ✗ Error: {result['error']}")
        else:
            vcolor = verdict_color[result["verdict"]]
            print(f"  ➤ {result['url']}")
            print(f"    Verdict    : {vcolor}{result['verdict']}{Style.RESET_ALL}")
            print(f"    Score      : {result['score']}")
            print(f"    Categories : {', '.join(result['categories']) if result['categories'] else 'None'}")
            print(f"    Screenshot : {result['screenshot']}")

    print("\n[ATTACHMENTS]")
    if report["attachments"]:
        for att in report["attachments"]:
            print(f"  ⚠ {att['filename']} ({att['type']})")
    else:
        print("  None found")

    print("\n[TECHNICAL HEADERS]")
    for key, value in report["headers"].items():
        print(f"  {key}: {value}")

    print("\n" + "="*50 + "\n")

def save_report(report):
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"Report saved to: {filename}")