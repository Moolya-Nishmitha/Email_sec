from backend.parser.email_parser import extract_ips, extract_urls
from backend.parser.header_analyzer import (
    analyze_headers,
    check_authentication,
    check_sender_mismatch,
    extract_received_ips,
)


def test_extract_urls():
    text = "Visit https://example.com and http://test.com"
    urls = extract_urls(text)

    assert "https://example.com" in urls
    assert "http://test.com" in urls


def test_extract_ips():
    text = "Connection from 192.168.1.10 and 8.8.8.8"
    ips = extract_ips(text)

    assert "192.168.1.10" in ips
    assert "8.8.8.8" in ips


def test_authentication_results():
    result = check_authentication(
        ["spf=pass dkim=pass dmarc=pass"]
    )

    assert result["spf"] == "PASS"
    assert result["dkim"] == "PASS"
    assert result["dmarc"] == "PASS"


def test_sender_mismatch():
    email_data = {
        "sender_email": "user@example.com",
        "reply_to": "attacker@evil.com",
        "return_path": "<user@example.com>",
    }

    warnings = check_sender_mismatch(email_data)

    assert "From and Reply-To domains do not match" in warnings


def test_received_ips():
    received = [
        "from mail.example.com (8.8.8.8)",
        "from relay.example.com (1.1.1.1)",
    ]

    ips = extract_received_ips(received)

    assert ips == ["8.8.8.8", "1.1.1.1"]


def test_analyze_headers():
    email_data = {
        "authentication_results": [
            "spf=fail dkim=pass dmarc=fail"
        ],
        "sender_email": "user@example.com",
        "reply_to": "attacker@evil.com",
        "return_path": "<user@example.com>",
        "received": ["from mail.example.com (8.8.8.8)"],
    }

    result = analyze_headers(email_data)

    assert result["authentication"]["spf"] == "FAIL"
    assert result["authentication"]["dmarc"] == "FAIL"
    assert result["received_ips"] == ["8.8.8.8"]
    assert len(result["indicators"]) >= 3