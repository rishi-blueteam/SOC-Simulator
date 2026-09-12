#!/usr/bin/env python3

import sys
import json
import subprocess
from email import policy
from email.parser import BytesParser
import re

def extract_urls_from_text(text: str) -> list:
    url_pattern = r"https?://[^\s<>\"']+"
    return list(set(re.findall(url_pattern, text)))

def analyze_eml(eml_path: str):
    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = msg
    spf = str(headers.get("Received-SPF", "")).lower()
    dmarc = str(headers.get("Authentication-Results", "")).lower()

    # Determine Header Auth Status
    auth_passed = True
    if "fail" in spf or "fail" in dmarc:
        auth_passed = False

    print(f"[*] Analyzing: {eml_path}")
    print(f"[*] Header Auth Status: {'PASS' if auth_passed else 'FAIL'}")

    # Extract Body and Links
    body = str(msg.get_body(preferencelist=('plain', 'html')))
    urls = extract_urls_from_text(body)

    url_analysis_result = None

    # CONDITION: If Headers look clean/safe BUT URLs are present, invoke the separate URL Correlator script!
    if auth_passed and urls:
        print("[!] Email Authentication passed, but embedded URLs were detected.")
        print("[*] Calling separate URL Correlator Tool (url_correlator.py)...")
        
        try:
            cmd = ["python3", "url_correlator.py"] + urls
            proc = subprocess.run(cmd, capture_output=True, text=True)
            url_analysis_result = json.loads(proc.stdout)
        except Exception as e:
            url_analysis_result = {"error": f"Failed to run URL tool: {str(e)}"}

    # Output Structured Result
    report = {
        "subject": headers.get("Subject", "N/A"),
        "from": headers.get("From", "N/A"),
        "auth_passed": auth_passed,
        "extracted_urls": urls,
        "url_enrichment": url_analysis_result
    }

    print("\n[ Final SOAR Pipeline Output ]")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 email_analyzer.py <file.eml>")
        sys.exit(1)
        
    analyze_eml(sys.argv[1])