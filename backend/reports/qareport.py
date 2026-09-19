"""
qareport.py
QA automation script for the Email Threat Detection Platform.
Uploads each .eml test file to the backend /analyze endpoint,
compares results against expected classification, and writes
a results table to docs/QA_RESULTS.md.

Usage:
    python qareport.py

Requires:
    pip install requests
"""

import requests
import os

# Change this once the backend teammate confirms the real URL/port
BACKEND_URL = "http://127.0.0.1:8000/analyze"

TEST_CASES = [
    {"id": "T01", "file": "samples/malicious/phishing_microsoft.eml", "expected": "HIGH RISK"},
    {"id": "T02", "file": "samples/malicious/bank_kyc.eml", "expected": "HIGH RISK"},
    {"id": "T03", "file": "samples/malicious/password_reset.eml", "expected": "MEDIUM/HIGH RISK"},
    {"id": "T04", "file": "samples/legitimate/normal_notification.eml", "expected": "LOW RISK"},
    {"id": "T05", "file": "samples/legitimate/newsletter.eml", "expected": "LOW RISK"},
    {"id": "E01", "file": "samples/edge_cases/no_url.eml", "expected": "LOW RISK"},
    {"id": "E02", "file": "samples/edge_cases/multiple_urls.eml", "expected": "ANY"},
    {"id": "E03", "file": "samples/edge_cases/missing_spf.eml", "expected": "ANY"},
]


def run_test(case):
    filepath = case["file"]
    if not os.path.exists(filepath):
        return {**case, "actual": "FILE NOT FOUND", "status": "BLOCKED"}

    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f, "message/rfc822")}
            response = requests.post(BACKEND_URL, files=files, timeout=15)
    except requests.exceptions.RequestException as e:
        return {**case, "actual": f"ERROR: {e}", "status": "BLOCKED"}

    if response.status_code != 200:
        return {**case, "actual": f"HTTP {response.status_code}", "status": "FAIL"}

    try:
        data = response.json()
    except ValueError:
        return {**case, "actual": "INVALID JSON RESPONSE", "status": "FAIL"}

    classification = str(data.get("classification", "UNKNOWN")).upper()
    score = data.get("score", "N/A")
    actual = f"{classification} ({score})"

    if case["expected"] == "ANY":
        status = "PASS" if classification != "UNKNOWN" else "FAIL"
        return {**case, "actual": actual, "status": status}

    expected_norm = case["expected"].upper().replace(" RISK", "")
    if "/" in expected_norm:
        options = [o.strip() for o in expected_norm.split("/")]
        passed = any(opt in classification for opt in options)
    else:
        passed = expected_norm in classification

    status = "PASS" if passed else "FAIL"
    return {**case, "actual": actual, "status": status}


def run_malformed_test():
    """Malformed .eml should return a clean error, not a 500 crash."""
    filepath = "samples/edge_cases/malformed.eml"
    if not os.path.exists(filepath):
        return {"id": "E04", "file": filepath, "expected": "Proper error (4xx)", "actual": "FILE NOT FOUND", "status": "BLOCKED"}
    try:
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f, "message/rfc822")}
            response = requests.post(BACKEND_URL, files=files, timeout=15)
    except requests.exceptions.RequestException as e:
        return {"id": "E04", "file": filepath, "expected": "Proper error (4xx)", "actual": f"ERROR: {e}", "status": "BLOCKED"}

    if 400 <= response.status_code < 500:
        status = "PASS"
    else:
        status = "FAIL"
    return {"id": "E04", "file": filepath, "expected": "Proper error (4xx)", "actual": f"HTTP {response.status_code}", "status": status}


def main():
    results = [run_test(case) for case in TEST_CASES]
    results.append(run_malformed_test())

    print(f"{'ID':<5}{'Expected':<20}{'Actual':<25}{'Status':<8}")
    print("-" * 60)
    for r in results:
        print(f"{r['id']:<5}{r['expected']:<20}{r['actual']:<25}{r['status']:<8}")

    passed = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    print("-" * 60)
    print(f"Total: {total}  Passed: {passed}  Failed: {total - passed}")

    os.makedirs("docs", exist_ok=True)
    with open("docs/QA_RESULTS.md", "w", encoding="utf-8") as out:
        out.write("# QA Automated Test Results\n\n")
        out.write("| ID | Expected | Actual | Status |\n")
        out.write("|---|---|---|---|\n")
        for r in results:
            out.write(f"| {r['id']} | {r['expected']} | {r['actual']} | {r['status']} |\n")
        out.write(f"\n**Total:** {total}  **Passed:** {passed}  **Failed:** {total - passed}\n")

    print("\nResults written to docs/QA_RESULTS.md")


if __name__ == "__main__":
    main()