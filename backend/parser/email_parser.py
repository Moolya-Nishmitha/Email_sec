from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
import re


def extract_body(msg):
    """Extract readable text from an email."""

    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():

            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass

    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            pass

    return "\n".join(body_parts)


def extract_urls(text):
    """Extract URLs from email body."""

    pattern = r'https?://[^\s<>"\']+'

    return list(set(re.findall(pattern, text)))


def extract_ips(text):
    """Extract IPv4 addresses from text."""

    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    return list(set(re.findall(pattern, text)))


def parse_email(file_path):
    """Parse an .eml file and return structured email data."""

    with open(file_path, "rb") as file:
        msg = BytesParser(
            policy=policy.default
        ).parse(file)

    body = extract_body(msg)

    from_header = msg.get("From", "")
    to_header = msg.get("To", "")

    sender_addresses = getaddresses([from_header])
    recipient_addresses = getaddresses([to_header])

    sender_email = (
        sender_addresses[0][1]
        if sender_addresses
        else ""
    )

    recipient_email = (
        recipient_addresses[0][1]
        if recipient_addresses
        else ""
    )

    return {
        "from": from_header,
        "sender_email": sender_email,
        "to": to_header,
        "recipient_email": recipient_email,
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "message_id": msg.get("Message-ID", ""),
        "received": msg.get_all("Received", []),
        "authentication_results": msg.get_all(
            "Authentication-Results", []
        ),
        "body": body,
        "urls": extract_urls(body),
        "ips": extract_ips(body),
    }