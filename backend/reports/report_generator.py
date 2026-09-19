"""
report_generator.py
Generates a human-readable investigation report from the combined
analysis result (parser + header analysis + detection + IOC intelligence).

This module is called by the /analyze endpoint after every upload,
right before the JSON response is returned to the frontend.

Expected input shape (adjust field names to match what parser.py,
threat_engine.py and ioc_analyzer.py actually return):

{
    "sender": "...",
    "reply_to": "...",
    "subject": "...",
    "spf": "FAIL",
    "dkim": "PASS",
    "dmarc": "FAIL",
    "score": 82,
    "classification": "HIGH RISK",
    "reasons": [...],
    "urls": [...],
    "domains": [...],
    "ips": [...],
    "header_warnings": [...]
}
"""

from datetime import datetime, timezone


def generate_report(data: dict) -> dict:
    """
    Takes the combined analysis result dict and returns a report dict
    containing both a structured summary and a formatted text version.

    This does NOT replace the raw JSON returned to the frontend — it
    adds a "report" key alongside it, so the frontend can show either
    the raw fields or the formatted text version.
    """

    sender = data.get("sender", "Unknown sender")
    reply_to = data.get("reply_to", "N/A")
    subject = data.get("subject", "No subject")

    spf = data.get("spf", "UNKNOWN")
    dkim = data.get("dkim", "UNKNOWN")
    dmarc = data.get("dmarc", "UNKNOWN")

    score = data.get("score", 0)
    classification = data.get("classification", "UNKNOWN")

    reasons = data.get("reasons", [])
    urls = data.get("urls", [])
    domains = data.get("domains", [])
    ips = data.get("ips", [])
    warnings = data.get("header_warnings", [])

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    # Build a plain-text formatted report (good for console/demo display)
    lines = []
    lines.append("=" * 50)
    lines.append("EMAIL THREAT INVESTIGATION REPORT")
    lines.append("=" * 50)
    lines.append(f"Generated: {generated_at}")
    lines.append("")
    lines.append(f"Sender:        {sender}")
    lines.append(f"Reply-To:      {reply_to}")
    lines.append(f"Subject:       {subject}")
    lines.append("")
    lines.append("Authentication:")
    lines.append(f"  SPF:   {spf}")
    lines.append(f"  DKIM:  {dkim}")
    lines.append(f"  DMARC: {dmarc}")
    lines.append("")
    lines.append(f"Threat Score:   {score}/100")
    lines.append(f"Classification: {classification}")
    lines.append("")

    if reasons:
        lines.append("Reasons Flagged:")
        for r in reasons:
            lines.append(f"  - {r}")
    else:
        lines.append("Reasons Flagged: None")
    lines.append("")

    if warnings:
        lines.append("Header Warnings:")
        for w in warnings:
            lines.append(f"  - {w}")
        lines.append("")

    lines.append(f"URLs Found ({len(urls)}):")
    for u in urls:
        lines.append(f"  - {u}")
    lines.append("")

    lines.append(f"Domains Found ({len(domains)}):")
    for d in domains:
        lines.append(f"  - {d}")
    lines.append("")

    lines.append(f"IP Addresses Found ({len(ips)}):")
    for ip in ips:
        lines.append(f"  - {ip}")
    lines.append("")
    lines.append("=" * 50)

    formatted_text = "\n".join(lines)

    return {
        "generated_at": generated_at,
        "summary": {
            "sender": sender,
            "reply_to": reply_to,
            "subject": subject,
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "score": score,
            "classification": classification,
            "reasons": reasons,
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "header_warnings": warnings,
        },
        "formatted_text": formatted_text,
    }