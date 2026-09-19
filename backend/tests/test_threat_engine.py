from backend.detection.threat_engine import analyze_threat


def test_clean_email_is_low_risk():
    header_analysis = {
        "authentication": {
            "spf": "PASS",
            "dkim": "PASS",
            "dmarc": "PASS",
        },
        "sender_warnings": [],
        "received_hops": 1,
    }

    ioc_analysis = {
        "ips": [],
        "domains": [],
        "urls": [],
    }

    result = analyze_threat(
        header_analysis,
        ioc_analysis,
    )

    assert result["score"] == 0
    assert result["classification"] == "LOW RISK"


def test_missing_authentication_adds_risk():
    header_analysis = {
        "authentication": {
            "spf": "UNKNOWN",
            "dkim": "UNKNOWN",
            "dmarc": "UNKNOWN",
        },
        "sender_warnings": [],
        "received_hops": 1,
    }

    ioc_analysis = {
        "ips": [],
        "domains": [],
        "urls": [],
    }

    result = analyze_threat(
        header_analysis,
        ioc_analysis,
    )

    assert result["score"] == 5
    assert result["classification"] == "LOW RISK"


def test_authentication_failures_increase_risk():
    header_analysis = {
        "authentication": {
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
        },
        "sender_warnings": [],
        "received_hops": 1,
    }

    ioc_analysis = {
        "ips": [],
        "domains": [],
        "urls": [],
    }

    result = analyze_threat(
        header_analysis,
        ioc_analysis,
    )

    assert result["score"] == 60
    assert result["classification"] == "HIGH RISK"


def test_sender_mismatch_increases_risk():
    header_analysis = {
        "authentication": {
            "spf": "PASS",
            "dkim": "PASS",
            "dmarc": "PASS",
        },
        "sender_warnings": [
            "From and Reply-To domains do not match",
        ],
        "received_hops": 1,
    }

    ioc_analysis = {
        "ips": [],
        "domains": [],
        "urls": [],
    }

    result = analyze_threat(
        header_analysis,
        ioc_analysis,
    )

    assert result["score"] == 15
    assert result["classification"] == "LOW RISK"


def test_multiple_urls_increase_risk():
    header_analysis = {
        "authentication": {
            "spf": "PASS",
            "dkim": "PASS",
            "dmarc": "PASS",
        },
        "sender_warnings": [],
        "received_hops": 1,
    }

    ioc_analysis = {
        "ips": [],
        "domains": [],
        "urls": [
            "https://example.com/one",
            "https://example.com/two",
            "https://example.com/three",
        ],
    }

    result = analyze_threat(
        header_analysis,
        ioc_analysis,
    )

    assert result["score"] == 10
    assert result["classification"] == "LOW RISK"


def test_combined_indicators_produce_high_risk():
    header_analysis = {
        "authentication": {
            "spf": "FAIL",
            "dkim": "FAIL",
            "dmarc": "FAIL",
        },
        "sender_warnings": [
            "From and Reply-To domains do not match",
        ],
        "received_hops": 6,
    }

    ioc_analysis = {
        "ips": [
            {
                "value": "203.0.113.10",
                "type": "public",
                "status": "success",
            },
        ],
        "domains": [],
        "urls": [
            "https://example.com/one",
            "https://example.com/two",
            "https://example.com/three",
        ],
    }

    result = analyze_threat(
        header_analysis,
        ioc_analysis,
    )

    assert result["score"] == 98
    assert result["classification"] == "HIGH RISK"
    assert len(result["reasons"]) > 0