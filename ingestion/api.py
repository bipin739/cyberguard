import os
import re
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, File, UploadFile, Query, HTTPException, status
from fastapi.responses import JSONResponse

from ingestion.detector import detect_file_type
from ingestion.router import route_to_engine
from shared.schema_validator import validate_event

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB in bytes
CHUNK_SIZE = 1024 * 1024  # 1 MB chunk

VALID_FORCE_TYPES = {
    "email",
    "network",
    "malware",
    "deepfake_audio",
    "deepfake_video",
    "threat_intel",
    "url",
    "unknown"
}


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a filename to prevent directory traversal and invalid paths.
    Strips directory separators, '../', and retains only safe characters.
    """
    if not filename:
        return "unnamed_file"
    # Normalize Windows/Unix path separators
    normalized = filename.replace("\\", "/")
    base_name = os.path.basename(normalized)
    # Strip leading/trailing dots and path traversal fragments
    base_name = re.sub(r'^\.+', '', base_name)
    # Replace unsafe characters with underscore
    sanitized = re.sub(r'[^a-zA-Z0-9_.\-]', '_', base_name)
    return sanitized if sanitized else "unnamed_file"


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    force_type: Optional[str] = Query(None, description="Manual engine category override")
):
    """
    Uploads a file, saves it securely to uploads/, classifies file type,
    routes to the target engine, validates the resulting event schema,
    and returns the JSON event.
    """
    if force_type is not None and force_type not in VALID_FORCE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid force_type '{force_type}'. Allowed values: {sorted(list(VALID_FORCE_TYPES))}"
        )

    clean_name = sanitize_filename(file.filename or "uploaded_file")
    unique_name = f"{uuid.uuid4().hex[:12]}_{clean_name}"
    save_path = (UPLOADS_DIR / unique_name).resolve()

    # Ensure target path stays strictly inside UPLOADS_DIR
    if not str(save_path).startswith(str(UPLOADS_DIR.resolve())):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename: Directory traversal attempt detected."
        )

    # Stream file to disk with 50MB size enforcement
    total_bytes = 0
    try:
        with open(save_path, "wb") as buffer:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_SIZE:
                    # Clean up partial file
                    buffer.close()
                    if save_path.exists():
                        save_path.unlink()
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"File size exceeds the 50MB limit ({total_bytes} bytes received)."
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        if save_path.exists():
            save_path.unlink()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save uploaded file: {str(exc)}"
        )
    finally:
        await file.close()

    # Determine file type
    if force_type:
        engine_type = force_type
    else:
        engine_type = detect_file_type(str(save_path))

    # Route to engine
    event = route_to_engine(engine_type, str(save_path))

    # Validate returned event against shared schema
    is_valid, errors = validate_event(event)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "message": "Engine produced an event that violates the shared schema",
                "schema_errors": errors,
                "event_data": event
            }
        )

    return JSONResponse(content=event, status_code=status.HTTP_200_OK)
