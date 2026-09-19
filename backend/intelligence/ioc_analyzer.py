import ipaddress
import json
import re
import socket
import urllib.request
from urllib.parse import urlparse

# ============================================================
# REGEX PATTERNS
# ============================================================

URL_PATTERN = re.compile(
    r"https?://[^\s<>'\"]+",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+[a-zA-Z]{2,}\b",
)


# ============================================================
# URL EXTRACTION
# ============================================================


def extract_urls(text):
    """
    Extract HTTP and HTTPS URLs from text.
    """

    if not text:
        return []

    urls = URL_PATTERN.findall(text)

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,;:!?)]}")

        if url and url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# ============================================================
# IP EXTRACTION
# ============================================================


def extract_ips(text):
    """
    Extract valid IPv4 addresses from text.
    """

    if not text:
        return []

    candidates = IP_PATTERN.findall(text)

    valid_ips = []

    for candidate in candidates:
        try:
            ip = ipaddress.ip_address(candidate)

            if ip.version == 4 and candidate not in valid_ips:
                valid_ips.append(candidate)

        except ValueError:
            continue

    return valid_ips


# ============================================================
# IP CLASSIFICATION
# ============================================================


def classify_ip(ip):
    """
    Classify an IP address.
    """

    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "loopback"

        if address.is_private:
            return "private"

        if address.is_reserved:
            return "reserved"

        if address.is_multicast:
            return "multicast"

        return "public"

    except ValueError:
        return "invalid"


# ============================================================
# IP GEOLOCATION / INTELLIGENCE
# ============================================================


def get_ip_intelligence(ip):
    """
    Retrieve basic geolocation and network information
    for a public IPv4 address.

    Non-public IPs are not sent to the external service.

    If the lookup fails, a structured fallback response
    is returned so the application can continue safely.
    """

    ip_type = classify_ip(ip)

    if ip_type != "public":
        return {
            "value": ip,
            "type": ip_type,
            "status": "not_enriched",
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "isp": None,
            "organization": None,
            "asn": None,
        }

    try:
        api_url = f"http://ip-api.com/json/{ip}"

        with urllib.request.urlopen(api_url, timeout=5) as response:
            data = json.loads(response.read().decode())

        if data.get("status") != "success":
            return {
                "value": ip,
                "type": ip_type,
                "status": "lookup_failed",
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "timezone": None,
                "isp": None,
                "organization": None,
                "asn": None,
            }

        return {
            "value": ip,
            "type": ip_type,
            "status": "success",
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "asn": data.get("as"),
        }

    except Exception:
        return {
            "value": ip,
            "type": ip_type,
            "status": "lookup_failed",
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "timezone": None,
            "isp": None,
            "organization": None,
            "asn": None,
        }


# ============================================================
# DOMAIN DNS INTELLIGENCE
# ============================================================


def resolve_domain(domain):
    """
    Resolve a domain name to its IPv4 addresses.

    Returns:
        dict containing the domain and resolved IP addresses.
    """

    result = {
        "domain": domain,
        "status": "lookup_failed",
        "resolved_ips": [],
    }

    if not domain:
        return result

    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET,
        )

        resolved_ips = sorted(
            {
                address[4][0]
                for address in addresses
            }
        )

        result["resolved_ips"] = resolved_ips

        if resolved_ips:
            result["status"] = "success"
        else:
            result["status"] = "no_records"

    except socket.gaierror:
        result["status"] = "no_records"

    except Exception:
        result["status"] = "lookup_failed"

    return result


# ============================================================
# DOMAIN EXTRACTION
# ============================================================


def extract_domains(text):
    """
    Extract domain names from text.

    Domains can be found inside URLs, email addresses,
    or as standalone domain names.
    """

    if not text:
        return []

    domains = []

    # Extract domains from URLs
    urls = extract_urls(text)

    for url in urls:
        try:
            hostname = urlparse(url).hostname

            if hostname:
                hostname = hostname.lower().rstrip(".")

                if hostname not in domains:
                    domains.append(hostname)

        except ValueError:
            continue

    # Extract standalone domains
    candidates = DOMAIN_PATTERN.findall(text)

    for candidate in candidates:
        candidate = candidate.lower().rstrip(".")

        # Ignore IP addresses
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass

        if candidate not in domains:
            domains.append(candidate)

    return domains


# ============================================================
# MAIN IOC ANALYZER
# ============================================================


def enrich_iocs(text):
    """
    Extract and enrich Indicators of Compromise (IOCs)
    from email text.

    Returns:
        dict containing:
        - IP intelligence
        - domain DNS intelligence
        - URLs
    """

    ips = extract_ips(text)
    domains = extract_domains(text)
    urls = extract_urls(text)

    ip_intelligence = [
        get_ip_intelligence(ip)
        for ip in ips
    ]

    domain_intelligence = [
        resolve_domain(domain)
        for domain in domains
    ]

    return {
        "ips": ip_intelligence,
        "domains": domain_intelligence,
        "urls": urls,
    }