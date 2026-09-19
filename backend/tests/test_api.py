from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_missing_file():
    response = client.post("/analyze")

    assert response.status_code == 422


def test_rejects_non_eml_file():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "malware.exe",
                b"fake executable",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 400


def test_rejects_empty_eml():
    response = client.post(
        "/analyze",
        files={
            "file": (
                "empty.eml",
                b"",
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 400


def test_accepts_eml():
    email_content = (
        b"From: attacker@example.com\r\n"
        b"To: victim@example.com\r\n"
        b"Subject: Test email\r\n"
        b"\r\n"
        b"This is a test email."
    )

    response = client.post(
        "/analyze",
        files={
            "file": (
                "test.eml",
                email_content,
                "message/rfc822",
            )
        },
    )

    assert response.status_code == 200
    assert response.json()["filename"] == "test.eml"