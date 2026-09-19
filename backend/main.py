import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile

from backend.detection.threat_engine import analyze_threat
from backend.intelligence.ioc_analyzer import enrich_iocs
from backend.parser.email_parser import parse_email
from backend.parser.header_analyzer import analyze_headers
from backend.reports.report_generator import generate_report

app = FastAPI(
    title="Email_sec API",
    description="Email Threat Detection Backend",
    version="1.0.0",
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "Email_sec API",
    }


@app.post("/analyze")
async def analyze_email(
    file: Annotated[UploadFile, File(...)],
):
    """
    Analyze an uploaded .eml file.

    Pipeline:

        .eml
          ↓
        email_parser
          ↓
        header_analyzer
          ↓
        ioc_analyzer
          ↓
        threat_engine
          ↓
        report_generator
          ↓
        JSON response
    """

    # --------------------------------------------------------
    # Validate filename
    # --------------------------------------------------------

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided",
        )

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported",
        )

    # --------------------------------------------------------
    # Read uploaded file
    # --------------------------------------------------------

    contents = await file.read()

    if not contents:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty",
        )

    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File exceeds the 10 MB limit",
        )

    # --------------------------------------------------------
    # Basic email structure validation
    # --------------------------------------------------------

    header_section = contents.split(
        b"\r\n\r\n",
        1,
    )[0]

    if b"\n\n" in contents and b"\r\n\r\n" not in contents:
        header_section = contents.split(
            b"\n\n",
            1,
        )[0]

    header_text = header_section.decode(
        "utf-8",
        errors="replace",
    )

    known_headers = (
        "From:",
        "To:",
        "Subject:",
        "Date:",
        "Message-ID:",
        "Received:",
        "Reply-To:",
        "Return-Path:",
        "Authentication-Results:",
        "Content-Type:",
    )

    has_known_header = any(
        header in header_text
        for header in known_headers
    )

    if not has_known_header:
        raise HTTPException(
            status_code=400,
            detail="Malformed or invalid .eml file",
        )

    # --------------------------------------------------------
    # Create temporary file
    # --------------------------------------------------------

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".eml",
            delete=False,
        ) as temp_file:
            temp_file.write(contents)
            temp_path = Path(temp_file.name)

        # ----------------------------------------------------
        # 1. Parse email
        # ----------------------------------------------------

        try:
            email_data = parse_email(temp_path)
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Unable to parse email: {exc}",
            ) from exc

        # ----------------------------------------------------
        # 2. Analyze headers
        # ----------------------------------------------------

        try:
            header_data = analyze_headers(email_data)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Header analysis failed: {exc}",
            ) from exc

        # ----------------------------------------------------
        # 3. Analyze IOCs
        # ----------------------------------------------------

        try:
            ioc_data = enrich_iocs(
                email_data.get("body", ""),
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"IOC analysis failed: {exc}",
            ) from exc

        # ----------------------------------------------------
        # 4. Calculate threat score
        # ----------------------------------------------------

        try:
            threat_data = analyze_threat(
                header_data,
                ioc_data,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Threat analysis failed: {exc}",
            ) from exc

        # ----------------------------------------------------
        # 5. Prepare flat fields for report generator
        # ----------------------------------------------------

        authentication = header_data.get(
            "authentication",
            {},
        )

        urls = ioc_data.get(
            "urls",
            [],
        )

        domains = [
            domain.get("domain")
            for domain in ioc_data.get("domains", [])
            if domain.get("domain")
        ]

        ips = [
            ip.get("value")
            for ip in ioc_data.get("ips", [])
            if ip.get("value")
        ]

        report_input = {
            "sender": email_data.get(
                "sender_email",
                email_data.get("from", ""),
            ),
            "reply_to": email_data.get(
                "reply_to",
                "",
            ),
            "subject": email_data.get(
                "subject",
                "",
            ),
            "spf": authentication.get(
                "spf",
                "UNKNOWN",
            ),
            "dkim": authentication.get(
                "dkim",
                "UNKNOWN",
            ),
            "dmarc": authentication.get(
                "dmarc",
                "UNKNOWN",
            ),
            "score": threat_data.get(
                "score",
                0,
            ),
            "classification": threat_data.get(
                "classification",
                "UNKNOWN",
            ),
            "reasons": threat_data.get(
                "reasons",
                [],
            ),
            "urls": urls,
            "domains": domains,
            "ips": ips,
            "header_warnings": header_data.get(
                "sender_warnings",
                [],
            ),
        }

        # ----------------------------------------------------
        # 6. Generate human-readable report
        # ----------------------------------------------------

        try:
            report = generate_report(
                report_input,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Report generation failed: {exc}",
            ) from exc

        # ----------------------------------------------------
        # 7. Return unified response
        # ----------------------------------------------------

        return {
            "filename": file.filename,

            "sender": report_input["sender"],
            "reply_to": report_input["reply_to"],
            "subject": report_input["subject"],

            "spf": report_input["spf"],
            "dkim": report_input["dkim"],
            "dmarc": report_input["dmarc"],

            "score": report_input["score"],
            "classification": report_input["classification"],

            "reasons": report_input["reasons"],
            "header_warnings": report_input["header_warnings"],

            "urls": urls,
            "domains": domains,
            "ips": ips,

            "header_analysis": header_data,
            "ioc_analysis": ioc_data,
            "threat_analysis": threat_data,

            "report": report,
        }

    finally:
        if temp_path is not None:
            temp_path.unlink(
                missing_ok=True,
            )