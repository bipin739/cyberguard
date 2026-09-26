import importlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

ENGINE_MAP = {
    "email": "engines.email.engine",
    "network": "engines.network.engine",
    "malware": "engines.malware.engine",
    "deepfake_audio": "engines.deepfake_audio.engine",
    "deepfake_video": "engines.deepfake_video.engine",
}


def route_to_engine(file_type: str, file_path: str) -> Dict[str, Any]:
    """
    Routes the given file to the appropriate engine module based on file_type,
    executes its process() function, and returns the event dictionary.

    If file_type is 'unknown' or unmapped, returns a valid unclassified event
    dict adhering to shared/event_schema.json without raising an exception.
    """
    if file_type in ENGINE_MAP:
        module_path = ENGINE_MAP[file_type]
        try:
            engine_module = importlib.import_module(module_path)
            process_fn = getattr(engine_module, "process")
            return process_fn(file_path)
        except Exception as exc:
            # Fallback event if engine execution encounters an unexpected error
            return {
                "event_id": f"evt_{uuid.uuid4()}",
                "source_engine": "threat_intel",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "engine_error",
                "confidence": 0.0,
                "entities": {},
                "iocs": [],
                "evidence": [
                    {
                        "description": f"Failed to execute engine {file_type}: {str(exc)}",
                        "field_ref": "engine_execution",
                        "weight": 0.0
                    }
                ],
                "raw_reference": file_path,
                "mitre_technique": None,
                "risk_level": None,
                "response_recommended": None
            }

    # Unknown or unclassified file
    return {
        "event_id": f"evt_{uuid.uuid4()}",
        "source_engine": "threat_intel",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "unclassified_file",
        "confidence": 0.0,
        "entities": {},
        "iocs": [],
        "evidence": [
            {
                "description": f"File type could not be definitively classified: '{file_type}'",
                "field_ref": "file_classification",
                "weight": 0.0
            }
        ],
        "raw_reference": file_path,
        "mitre_technique": None,
        "risk_level": None,
        "response_recommended": None
    }
