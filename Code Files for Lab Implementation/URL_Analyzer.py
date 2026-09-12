#!/usr/bin/env python3

import os
import sys
import json
import requests
from urllib.parse import urlparse

# =====================================================
# Helper: Environment Sanitizer
# =====================================================
def get_clean_env(var_name: str) -> str:
    """Retrieve environment variable and strip extraneous quotes/spaces."""
    raw_val = os.getenv(var_name, "")
    return raw_val.strip().strip('"').strip("'")

# =====================================================
# Engine 1: VirusTotal API v3
# =====================================================
def check_virustotal(domain: str) -> dict:
    api_key = get_clean_env("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"status": "SKIPPED", "reason": "No Key"}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    
    try:
        res = requests.get(url, headers=headers, timeout=6)
        if res.status_code == 200:
            stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "SUCCESS",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)
            }
        return {"status": "ERROR", "reason": f"HTTP {res.status_code}"}
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}



# =====================================================
# Engine 2: URLhaus API (abuse.ch)
# =====================================================
def check_urlhaus(url_to_check: str) -> dict:
    api_key = get_clean_env("URLHAUS_API_KEY")
    if not api_key:
        return {"status": "SKIPPED", "reason": "URLHAUS_API_KEY missing"}

    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    
    # Custom Auth-Key header required by abuse.ch
    headers = {
        "Auth-Key": api_key
    }
    data = {
        "url": url_to_check
    }

    try:
        res = requests.post(api_url, data=data, headers=headers, timeout=6)
        if res.status_code == 200:
            result = res.json()
            query_status = result.get("query_status")
            
            if query_status == "ok":
                return {
                    "status": "MALICIOUS",
                    "threat": result.get("threat", "malware"),
                    "tags": result.get("tags", [])
                }
            elif query_status == "no_results":
                return {"status": "CLEAN"}
            else:
                return {"status": "ERROR", "reason": f"URLhaus Status: {query_status}"}
        elif res.status_code == 401 or res.status_code == 403:
            return {"status": "ERROR", "reason": "HTTP 401/403: Invalid URLhaus Auth-Key"}
        else:
            return {"status": "ERROR", "reason": f"HTTP {res.status_code}"}
            
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}
    
# =====================================================
# Engine 3: URLScan.io API
# =====================================================
def check_urlscan_history(domain: str) -> dict:
    api_key = get_clean_env("URLSCAN_API_KEY")
    if not api_key:
        return {"status": "SKIPPED", "reason": "URLSCAN_API_KEY missing"}

    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    query = f"page.domain:{domain} OR task.domain:{domain}"
    search_url = f"https://urlscan.io/api/v1/search/?q={query}"

    try:
        res = requests.get(search_url, headers=headers, timeout=6)
        if res.status_code != 200:
            return {"status": "ERROR", "reason": f"Search HTTP {res.status_code}"}

        search_data = res.json()
        results = search_data.get("results", [])
        if not results:
            return {"status": "CLEAN", "historical_malicious_scans": 0}

        latest_scan_uuid = results[0].get("_id") or results[0].get("task", {}).get("uuid")
        if not latest_scan_uuid:
            return {"status": "ERROR", "reason": "No UUID found"}

        result_url = f"https://urlscan.io/api/v1/result/{latest_scan_uuid}/"
        res_full = requests.get(result_url, headers=headers, timeout=6)
        
        if res_full.status_code == 200:
            full_data = res_full.json()
            verdicts = full_data.get("verdicts", {})
            overall = verdicts.get("overall", {})
            urlscan_v = verdicts.get("urlscan", {})

            is_malicious = (
                overall.get("malicious") is True or
                urlscan_v.get("malicious") is True or
                overall.get("score", 0) > 0
            )

            return {
                "status": "SUCCESS",
                "historical_malicious_scans": 1 if is_malicious else 0,
                "score": overall.get("score", 0),
                "categories": overall.get("categories", []),
                "brands": overall.get("brands", []),
                "scan_uuid": latest_scan_uuid
            }
        return {"status": "ERROR", "reason": f"Result HTTP {res_full.status_code}"}

    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}

# =====================================================
# Engine 4: Google Safe Browsing API v4
# =====================================================
def check_google_safebrowsing(target_url: str) -> dict:
    api_key = get_clean_env("GOOGLE_SAFE_BROWSING_API_KEY")
    if not api_key:
        return {"status": "SKIPPED", "reason": "No Key"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {
            "clientId": "soc-pipeline",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": target_url}]
        }
    }

    try:
        res = requests.post(endpoint, json=payload, headers=headers, timeout=6)
        if res.status_code == 200:
            matches = res.json().get("matches", [])
            return {
                "status": "SUCCESS",
                "is_malicious": len(matches) > 0,
                "threat_types": [m.get("threatType") for m in matches]
            }
        return {"status": "ERROR", "reason": f"HTTP {res.status_code}: {res.text}"}
    except Exception as e:
        return {"status": "ERROR", "reason": str(e)}

# =====================================================
# Redirect Unroller
# =====================================================
def trace_redirects(url: str) -> dict:
    try:
        res = requests.head(url, allow_redirects=True, timeout=4)
        return {
            "initial_url": url,
            "final_url": res.url,
            "redirected": url != res.url
        }
    except Exception:
        return {"initial_url": url, "final_url": url, "redirected": False}


# =====================================================
# Correlation & Consensus Engine
# =====================================================
def correlate_url(target_url: str) -> dict:
    target_url = target_url.strip()
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    trace = trace_redirects(target_url)
    final_url = trace["final_url"]
    parsed_url = urlparse(final_url)
    final_domain = parsed_url.netloc.split(":")[0] if parsed_url.netloc else parsed_url.path.split("/")[0]

    # 1. Query All 4 Engines
    raw_reports = {
        "virustotal": check_virustotal(final_domain),
        "urlhaus": check_urlhaus(final_url),
        "urlscan": check_urlscan_history(final_domain),
        "google_safe_browsing": check_google_safebrowsing(final_url)
    }

    # 2. Score Aggregation & Metrics
    malicious_indicators = 0
    flags = []
    
    # Categorization counters
    metrics = {
        "total_tools_run": len(raw_reports),
        "malicious_count": 0,
        "clean_count": 0,
        "error_or_skipped_count": 0
    }

    # VirusTotal Evaluation
    vt = raw_reports["virustotal"]
    if vt.get("status") == "SUCCESS":
        if vt.get("malicious", 0) > 0:
            malicious_indicators += 1
            metrics["malicious_count"] += 1
            flags.append(f"VirusTotal detected {vt['malicious']} engines flagging domain")
        else:
            metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    # URLhaus Evaluation
    uh = raw_reports["urlhaus"]
    if uh.get("status") == "MALICIOUS":
        malicious_indicators += 2
        metrics["malicious_count"] += 1
        flags.append(f"URLhaus threat match: {uh.get('threat')}")
    elif uh.get("status") == "CLEAN":
        metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    # URLScan Evaluation
    us = raw_reports["urlscan"]
    if us.get("status") == "SUCCESS":
        if us.get("historical_malicious_scans", 0) > 0:
            malicious_indicators += 1
            metrics["malicious_count"] += 1
            flags.append(f"URLScan.io flagged malicious activity (Score: {us.get('score')})")
        else:
            metrics["clean_count"] += 1
    elif us.get("status") == "CLEAN":
        metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    # Google Safe Browsing Evaluation
    gsb = raw_reports["google_safe_browsing"]
    if gsb.get("status") == "SUCCESS":
        if gsb.get("is_malicious"):
            malicious_indicators += 2
            metrics["malicious_count"] += 1
            flags.append(f"Google Safe Browsing flagged threats: {', '.join(gsb.get('threat_types', []))}")
        else:
            metrics["clean_count"] += 1
    else:
        metrics["error_or_skipped_count"] += 1

    if trace["redirected"]:
        flags.append(f"HTTP Redirect detected: {trace['initial_url']} -> {final_url}")

    # 3. Overall Verdict Decision
    if malicious_indicators >= 2:
        verdict = "MALICIOUS"
    elif malicious_indicators == 1 or trace["redirected"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "url_trace": trace,
        "final_domain": final_domain,
        "verdict": verdict,
        "threat_score": malicious_indicators,
        "engine_summary": metrics,
        "triggered_flags": flags,
        "raw_engine_reports": raw_reports
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python3 url_correlator.py <URL>"}))
        sys.exit(1)

    url_to_test = sys.argv[1]
    report = correlate_url(url_to_test)
    print(json.dumps(report, indent=2))