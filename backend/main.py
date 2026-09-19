import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile

app = FastAPI(
    title="DeepTrace API",
    description="Email threat analysis backend",
    version="1.0.0",
)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "DeepTrace API",
    }


@app.post("/analyze")
async def analyze_email(
    file: Annotated[UploadFile, File(...)],
):
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

    with tempfile.NamedTemporaryFile(
        suffix=".eml",
        delete=False,
    ) as temp_file:
        temp_file.write(contents)
        temp_path = Path(temp_file.name)

    try:
        # Team analysis modules will be integrated here.
        result = {
            "filename": file.filename,
            "status": "received",
            "message": "Email uploaded successfully",
        }

        return result

    finally:
        temp_path.unlink(missing_ok=True)