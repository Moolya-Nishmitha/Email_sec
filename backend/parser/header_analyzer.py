import re


def check_authentication(authentication_results):
    """
    Analyze SPF, DKIM and DMARC results from
    Authentication-Results headers.
    """

    text = " ".join(authentication_results).lower()

    result = {
        "spf": "UNKNOWN",
        "dkim": "UNKNOWN",
        "dmarc": "UNKNOWN"
    }

    spf_match = re.search(
        r"\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
        text
    )

    dkim_match = re.search(
        r"\bdkim=(pass|fail|neutral|none|temperror|permerror)\b",
        text
    )

    dmarc_match = re.search(
        r"\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b",
        text
    )

    if spf_match:
        result["spf"] = spf_match.group(1).upper()

    if dkim_match:
        result["dkim"] = dkim_match.group(1).upper()

    if dmarc_match:
        result["dmarc"] = dmarc_match.group(1).upper()

    return result


def check_sender_mismatch(email_data):
    """
    Check whether From, Reply-To and Return-Path
    use different domains.
    """

    warnings = []

    sender = email_data.get("sender_email", "").lower()
    reply_to = email_data.get("reply_to", "").lower()
    return_path = email_data.get("return_path", "").lower()

    # Clean Return-Path
    return_path = return_path.replace("<", "").replace(">", "")

    if sender and reply_to and "@" in sender and "@" in reply_to:

        sender_domain = sender.split("@")[-1]
        reply_domain = reply_to.split("@")[-1]

        if sender_domain != reply_domain:
            warnings.append(
                "From and Reply-To domains do not match"
            )

    if sender and return_path and "@" in sender and "@" in return_path:

        sender_domain = sender.split("@")[-1]
        return_domain = return_path.split("@")[-1]

        if sender_domain != return_domain:
            warnings.append(
                "From and Return-Path domains do not match"
            )

    return warnings


def extract_received_ips(received_headers):
    """
    Extract IPv4 addresses from Received headers.
    """

    ips = []

    for header in received_headers:

        found_ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            header
        )

        ips.extend(found_ips)

    return list(dict.fromkeys(ips))


def analyze_headers(email_data):
    """
    Perform complete email header analysis.
    """

    authentication = check_authentication(
        email_data.get("authentication_results", [])
    )

    warnings = check_sender_mismatch(email_data)

    received_ips = extract_received_ips(
        email_data.get("received", [])
    )

    return {
        "authentication": authentication,
        "sender_warnings": warnings,
        "received_hops": len(
            email_data.get("received", [])
        ),
        "received_ips": received_ips
    }