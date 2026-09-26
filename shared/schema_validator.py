import json
import os
from pathlib import Path
from typing import Tuple, List
import jsonschema
from jsonschema import Draft7Validator

# Load schema relative to this file's location
SCHEMA_PATH = Path(__file__).resolve().parent / "event_schema.json"

_loaded_schema = None
_validator = None


def _get_validator():
    global _loaded_schema, _validator
    if _validator is None:
        if not SCHEMA_PATH.exists():
            raise FileNotFoundError(f"Schema file not found at: {SCHEMA_PATH}")
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            _loaded_schema = json.load(f)
        _validator = Draft7Validator(_loaded_schema)
    return _validator


def validate_event(event: dict) -> Tuple[bool, List[str]]:
    """
    Validates a given event dictionary against shared/event_schema.json
    using the jsonschema library.

    Returns:
        (True, []) if valid, or (False, [list of error messages]) if invalid.
    """
    try:
        validator = _get_validator()
        errors = list(validator.iter_errors(event))
        if not errors:
            return True, []
        
        error_messages = []
        for err in errors:
            field = " -> ".join([str(p) for p in err.absolute_path]) if err.absolute_path else "root"
            error_messages.append(f"[{field}] {err.message}")
        return False, error_messages
    except Exception as exc:
        return False, [f"Validation exception: {str(exc)}"]


if __name__ == "__main__":
    example_events_path = Path(__file__).resolve().parent / "example_events.json"
    
    print("=" * 60)
    print("CyberGuard Shared Schema Validator Test")
    print(f"Schema: {SCHEMA_PATH}")
    print(f"Examples: {example_events_path}")
    print("=" * 60)

    if not example_events_path.exists():
        print(f"Error: {example_events_path} not found.")
        exit(1)

    with open(example_events_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    # Validate events at index 0, 1, and 2
    # Index 3 is skipped because it represents correlation diff updates, not a full event
    indices_to_validate = [0, 1, 2]
    all_passed = True

    for idx in indices_to_validate:
        if idx >= len(events):
            print(f"[!] Warning: Index {idx} not found in example_events.json")
            continue
        
        event = events[idx]
        engine_name = event.get("source_engine", "unknown")
        event_id = event.get("event_id", f"index_{idx}")
        comment = event.get("_comment", "")
        
        is_valid, errors = validate_event(event)
        
        print(f"\n[Index {idx}] {engine_name.upper()} Engine Event ({event_id})")
        if comment:
            print(f"  Comment: {comment}")
            
        if is_valid:
            print("  Status:  PASSED (Valid against draft-07 event schema)")
        else:
            all_passed = False
            print("  Status:  FAILED")
            for err in errors:
                print(f"    - Error: {err}")

    # Index 3 explanation
    if len(events) > 3:
        print("\n[Index 3] CORRELATION ENGINE Diff Updates")
        print(f"  Comment: {events[3].get('_comment', '')}")
        print("  Status:  SKIPPED (Intentional: Correlation update diff, not a full event object)")

    print("\n" + "=" * 60)
    if all_passed:
        print("RESULT: ALL SPECIFIED EXAMPLE EVENTS VALIDATED SUCCESSFULLY!")
    else:
        print("RESULT: SCHEMA VALIDATION FAILED ON ONE OR MORE EVENTS.")
    print("=" * 60)
