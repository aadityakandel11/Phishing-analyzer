# Automated Phishing Analysis Pipeline 

## OVERVIEW
A python automation tool that analyzes phishing emails and automatically generates threat intelligence reports. Built to demonstrate SOC automation skills and reduce manual triage time. 

## WHAT IT DOES 
- Parses raw .eml phishing email files 
- Extract all ULs, attachments, and technical headers automatically 
- Queries Virustotal API to check each URL against 70+ security engines 
- Queries URLScan.io API to sandbox suspicious URLs and capture screenshots 
- Generates a color-coded threat with an overall verdict 
- Saves structured JSON reports for documentation 

## Results
Analyzed 20 confirmed phishing samples from public sources. 

| Metric | Result |
--------------------
| Emails analyzed | 20 |
| Malicious Detected | 8|
| Suspicious detected | 0 |
| Clean | 12 |
| Avg analysis time | ~90 seconds |
| Time saved per email | ~13 minutes |

## Tech Stack 
- Python 3.12
- VirusTotal API v3 
- URLscan.io API
- Libraries: requests, python-whois, dnspython, colorama, python-dotenv

## How to Run 
1. Clone the repo 
2. Install dependencies: 'pip3 install -r requrements.txt'
3. Add your API keys to a '.env' file 
4. Run: 'python3 main.py emails/your_email.eml'

## Sample Output 

==================================================
       PHISHING ANALYSIS REPORT
==================================================
Timestamp : 2026-03-24 20:32:32
Verdict   : CLEAN
--------------------------------------------------

[EMAIL DETAILS]
  Subject  : The Startling Reality of Energy Inefficiency.
  From     : "Eco Wisdom: Elon" <agrensophie@centromedicogallo.com>
  To       : "phishing@pot" <phishing@pot>
  Reply-To : None
  Date     : Tue, 10 Oct 2023 10:39:40 -0700

## Skills Demonstrated 
- Python scripting in a security context 
- REST API integration 
- Automated IOC enviornment 
- SOC automation mindset 


