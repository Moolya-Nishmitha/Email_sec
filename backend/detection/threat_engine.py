"""
Threat detection and risk scoring engine.

Consumes:
- Header analysis from header_analyzer.py
- IOC intelligence from ioc_analyzer.py

Produces:
- score
- classification
- reasons
- detailed findings
- score breakdown

The engine uses explainable heuristic rules rather than
opaque/random classifications.
"""

from __future__ import annotations


# ============================================================
# SCORE WEIGHTS
# ============================================================

SCORE_WEIGHTS = {
    "spf_fail": 20,
    "dkim_fail": 20,
    "dmarc_fail": 20,
    "sender_mismatch": 15,
    "suspicious_ip": 10,
    "suspicious_domain": 10,
    "external_url": 5,
    "multiple_urls": 5,
    "no_authentication": 5,
    "multiple_received_hops": 3,
}


# ============================================================
# CLASSIFICATION
# ============================================================


def get_classification(score: int) -> str:
    """Convert a score into the project's expected classification."""

    if score >= 50:
        return "HIGH RISK"

    if score >= 25:
        return "MEDIUM RISK"

    return "LOW RISK"


# ============================================================
# AUTHENTICATION ANALYSIS
# ============================================================


def analyze_authentication(
    header_analysis: dict,
) -> tuple[int, list[dict]]:
    """Analyze SPF, DKIM and DMARC results."""

    score = 0
    findings = []

    authentication = header_analysis.get(
        "authentication",
        {},
    )

    checks = [
        ("spf", "SPF", SCORE_WEIGHTS["spf_fail"]),
        ("dkim", "DKIM", SCORE_WEIGHTS["dkim_fail"]),
        ("dmarc", "DMARC", SCORE_WEIGHTS["dmarc_fail"]),
    ]

    known_result = False

    for key, name, weight in checks:
        result = str(
            authentication.get(key, "UNKNOWN")
        ).upper()

        if result != "UNKNOWN":
            known_result = True

        if result == "FAIL":
            score += weight

            findings.append(
                {
                    "type": "authentication_failure",
                    "severity": "high",
                    "indicator": name,
                    "message": f"{name} authentication failed",
                    "score": weight,
                }
            )

        elif result in {
            "SOFTFAIL",
            "PERMERROR",
            "TEMPERROR",
        }:
            partial_score = weight // 2
            score += partial_score

            findings.append(
                {
                    "type": "authentication_warning",
                    "severity": "medium",
                    "indicator": name,
                    "message": (
                        f"{name} returned {result.lower()}"
                    ),
                    "score": partial_score,
                }
            )

    if not known_result:
        score += SCORE_WEIGHTS["no_authentication"]

        findings.append(
            {
                "type": "authentication_missing",
                "severity": "low",
                "indicator": "Authentication-Results",
                "message": (
                    "No SPF, DKIM or DMARC result was available"
                ),
                "score": SCORE_WEIGHTS["no_authentication"],
            }
        )

    return score, findings


# ============================================================
# SENDER ANALYSIS
# ============================================================


def analyze_sender(
    header_analysis: dict,
) -> tuple[int, list[dict]]:
    """Analyze From, Reply-To and Return-Path mismatches."""

    score = 0
    findings = []

    warnings = header_analysis.get(
        "sender_warnings",
        [],
    )

    for warning in warnings:
        score += SCORE_WEIGHTS["sender_mismatch"]

        findings.append(
            {
                "type": "sender_mismatch",
                "severity": "high",
                "indicator": "sender_identity",
                "message": warning,
                "score": SCORE_WEIGHTS["sender_mismatch"],
            }
        )

    return score, findings


# ============================================================
# IOC ANALYSIS
# ============================================================


def analyze_iocs(
    ioc_analysis: dict,
) -> tuple[int, list[dict]]:
    """Analyze IP, domain and URL intelligence."""

    score = 0
    findings = []

    ips = ioc_analysis.get("ips", [])
    domains = ioc_analysis.get("domains", [])
    urls = ioc_analysis.get("urls", [])

    # --------------------------------------------------------
    # IP intelligence
    # --------------------------------------------------------

    public_ips = []

    for ip_data in ips:
        ip_type = str(
            ip_data.get("type", "")
        ).lower()

        if ip_type == "public":
            public_ips.append(ip_data)

    if public_ips:
        ip_score = min(
            len(public_ips) * SCORE_WEIGHTS["suspicious_ip"],
            30,
        )

        score += ip_score

        findings.append(
            {
                "type": "ip_intelligence",
                "severity": "medium",
                "indicator": "public_ip",
                "message": (
                    f"{len(public_ips)} public IP address(es) "
                    "were identified"
                ),
                "score": ip_score,
            }
        )

    # --------------------------------------------------------
    # Domain intelligence
    # --------------------------------------------------------

    unresolved_domains = []

    for domain_data in domains:
        status = str(
            domain_data.get("status", "")
        ).lower()

        if status == "lookup_failed":
            unresolved_domains.append(domain_data)

    if unresolved_domains:
        domain_score = min(
            len(unresolved_domains)
            * SCORE_WEIGHTS["suspicious_domain"],
            30,
        )

        score += domain_score

        findings.append(
            {
                "type": "domain_intelligence",
                "severity": "medium",
                "indicator": "unresolved_domain",
                "message": (
                    f"{len(unresolved_domains)} domain(s) "
                    "could not be resolved"
                ),
                "score": domain_score,
            }
        )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    url_count = len(urls)

    if url_count > 0:
        score += SCORE_WEIGHTS["external_url"]

        findings.append(
            {
                "type": "url_presence",
                "severity": "low",
                "indicator": "external_url",
                "message": (
                    f"Email contains {url_count} URL(s)"
                ),
                "score": SCORE_WEIGHTS["external_url"],
            }
        )

    if url_count >= 3:
        score += SCORE_WEIGHTS["multiple_urls"]

        findings.append(
            {
                "type": "multiple_urls",
                "severity": "medium",
                "indicator": "multiple_urls",
                "message": (
                    "Email contains multiple external URLs"
                ),
                "score": SCORE_WEIGHTS["multiple_urls"],
            }
        )

    return score, findings


# ============================================================
# ROUTING ANALYSIS
# ============================================================


def analyze_routing(
    header_analysis: dict,
) -> tuple[int, list[dict]]:
    """Analyze received-header routing complexity."""

    score = 0
    findings = []

    received_hops = header_analysis.get(
        "received_hops",
        0,
    )

    if received_hops >= 5:
        score += SCORE_WEIGHTS["multiple_received_hops"]

        findings.append(
            {
                "type": "routing_complexity",
                "severity": "low",
                "indicator": "received_hops",
                "message": (
                    f"Email passed through {received_hops} "
                    "received hops"
                ),
                "score": SCORE_WEIGHTS[
                    "multiple_received_hops"
                ],
            }
        )

    return score, findings


# ============================================================
# MAIN ENGINE
# ============================================================


def analyze_threat(
    header_analysis: dict,
    ioc_analysis: dict,
) -> dict:
    """
    Calculate the overall threat assessment.

    Returns a dictionary compatible with qareport.py
    and report_generator.py.
    """

    total_score = 0
    findings = []

    analyzers = [
        analyze_authentication(header_analysis),
        analyze_sender(header_analysis),
        analyze_iocs(ioc_analysis),
        analyze_routing(header_analysis),
    ]

    for component_score, component_findings in analyzers:
        total_score += component_score
        findings.extend(component_findings)

    total_score = min(
        max(total_score, 0),
        100,
    )

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }

    findings.sort(
        key=lambda finding: severity_order.get(
            finding.get("severity", "low"),
            3,
        )
    )

    reasons = [
        finding["message"]
        for finding in findings
    ]

    score_breakdown = [
        {
            "indicator": finding["indicator"],
            "score": finding["score"],
        }
        for finding in findings
    ]

    classification = get_classification(
        total_score
    )

    return {
        "score": total_score,
        "classification": classification,
        "reasons": reasons,
        "findings": findings,
        "score_breakdown": score_breakdown,
        "finding_count": len(findings),
    }