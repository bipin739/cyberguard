import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from fastapi import APIRouter, File, UploadFile, Query, HTTPException, status
from fastapi.responses import JSONResponse

from ingestion.detector import detect_file_type
from ingestion.router import route_to_engine
from shared.schema_validator import validate_event
from correlation.correlator import correlation_engine, Campaign
from risk_explanation_response import evaluate_campaign, RESPONSE_PLAYBOOKS

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/api/reset")
async def reset_demo_data():
    """
    Clears all campaigns and events from the correlation engine's in-memory state
    and removes all uploaded files from uploads/ directory (except .gitkeep).
    """
    correlation_engine.reset()

    # Clear uploads directory
    cleared_files_count = 0
    if UPLOADS_DIR.exists():
        for file_path in UPLOADS_DIR.iterdir():
            if file_path.is_file() and file_path.name != ".gitkeep":
                try:
                    file_path.unlink()
                    cleared_files_count += 1
                except Exception:
                    pass

    return {
        "status": "ok",
        "message": f"Successfully cleared all in-memory campaigns and {cleared_files_count} upload file(s)."
    }


@router.get("/api/stats")
async def get_stats():
    """Returns overview KPI metrics for the SOC dashboard."""
    campaigns = correlation_engine.get_all_campaigns()
    for c in campaigns:
        evaluate_campaign(c)

    critical_count = sum(1 for c in campaigns if c.risk_level == "critical")
    high_count = sum(1 for c in campaigns if c.risk_level == "high")
    medium_count = sum(1 for c in campaigns if c.risk_level == "medium")
    low_count = sum(1 for c in campaigns if c.risk_level in ("low", "safe"))

    total_events = sum(len(c.events) for c in campaigns)

    return {
        "total_campaigns": len(campaigns),
        "total_events": total_events,
        "critical_campaigns": critical_count,
        "high_campaigns": high_count,
        "medium_campaigns": medium_count,
        "low_campaigns": low_count,
        "active_engines": [
            {"id": "email", "name": "Email Phishing & Headers", "status": "online"},
            {"id": "network", "name": "Network & Auth Telemetry", "status": "online"},
            {"id": "malware", "name": "Malware & Binary Analysis", "status": "online"},
            {"id": "deepfake_audio", "name": "Deepfake Voice Biometrics", "status": "online"},
            {"id": "deepfake_video", "name": "Deepfake Visual Artifacts", "status": "online"}
        ]
    }


@router.get("/api/campaigns")
async def get_campaigns():
    """Returns all active correlated campaigns with evaluated risk scores and XAI."""
    campaigns = correlation_engine.get_all_campaigns()
    for c in campaigns:
        evaluate_campaign(c)
    return [c.to_dict() for c in campaigns]


@router.get("/api/campaigns/{campaign_id}")
async def get_campaign_detail(campaign_id: str):
    """Returns detailed campaign metadata, events, explanation, and response recommendations."""
    campaign = correlation_engine.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")
    evaluate_campaign(campaign)
    return campaign.to_dict()


@router.get("/api/campaigns/{campaign_id}/graph")
async def get_campaign_attack_graph(campaign_id: str):
    """Returns node-and-edge attack graph structure for visualization."""
    campaign = correlation_engine.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")
    evaluate_campaign(campaign)
    return correlation_engine.build_attack_graph(campaign_id)


@router.get("/api/events")
async def get_all_events():
    """Returns all ingested and indexed events."""
    events = list(correlation_engine.event_index.values())
    return sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)


@router.post("/api/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    force_type: Optional[str] = Query(None)
):
    """
    Unified end-to-end pipeline:
    1. Ingestion & File Type Detection
    2. Engine Processing
    3. Graph Correlation & Campaign Grouping
    4. Multi-Factor Risk Scoring
    5. Explainable AI Narrative Generation
    6. Response Playbook Recommendation
    """
    clean_name = (file.filename or "sample").replace("/", "_").replace("\\", "_")
    unique_name = f"{uuid.uuid4().hex[:10]}_{clean_name}"
    save_path = UPLOADS_DIR / unique_name

    # Save file
    content = await file.read()
    with open(save_path, "wb") as f:
        f.write(content)

    # 1. Detect file type
    file_type = force_type if force_type else detect_file_type(str(save_path))

    # 2. Route to engine
    raw_event = route_to_engine(file_type, str(save_path))

    # Validate against schema
    is_valid, errs = validate_event(raw_event)
    if not is_valid:
        raise HTTPException(
            status_code=500,
            detail={"message": "Engine produced invalid schema", "errors": errs}
        )

    # 3. Correlate event into campaign
    enriched_event = correlation_engine.process_event(raw_event)
    campaign_id = enriched_event["entities"]["campaign_id"]
    campaign = correlation_engine.get_campaign(campaign_id)

    # 4, 5, 6. Evaluate campaign (Risk, Explainer, Response)
    evaluate_campaign(campaign)

    return {
        "status": "success",
        "event": enriched_event,
        "campaign": campaign.to_dict(),
        "attack_graph": correlation_engine.build_attack_graph(campaign_id)
    }


@router.post("/api/campaigns/{campaign_id}/respond")
async def execute_response_action(
    campaign_id: str,
    action: Optional[str] = Query(None)
):
    """Simulates the execution of automated containment actions for a campaign."""
    campaign = correlation_engine.get_campaign(campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")

    selected_action = action or campaign.response_recommended or "quarantine_email"
    playbook = RESPONSE_PLAYBOOKS.get(selected_action, RESPONSE_PLAYBOOKS["quarantine_email"])

    execution_logs = [
        f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] INITIATED: Automated containment playbook '{playbook['title']}'",
        f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] TARGETS: {', '.join([f'{k}={v}' for k, v in campaign.entities.items()])}",
        f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] STEP 1/3: {playbook['steps'][0]} -> SUCCESS",
        f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] STEP 2/3: {playbook['steps'][1]} -> SUCCESS",
        f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] STEP 3/3: {playbook['steps'][2]} -> SUCCESS",
        f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] COMPLETE: Campaign {campaign_id} containment verified."
    ]

    return {
        "status": "executed",
        "campaign_id": campaign_id,
        "action": selected_action,
        "playbook": playbook,
        "execution_logs": execution_logs
    }


@router.post("/api/load_scenario/{scenario_id}")
async def load_threat_scenario(scenario_id: str):
    """Preloads high-fidelity multi-stage attack scenarios for live demonstration."""
    if scenario_id == "phishing_lateral_movement":
        # Scenario 1: Spearphishing -> Credential Theft -> New Device Login -> Memory Injection Malware
        ev_email = {
            "event_id": f"evt_{uuid.uuid4()}",
            "source_engine": "email",
            "timestamp": "2026-09-26T09:12:00Z",
            "event_type": "phishing_email_detected",
            "confidence": 0.94,
            "entities": {
                "user_email": "bipin.p@company.com",
                "domain": "paypa1-secure.com",
                "url": "https://paypa1-secure.com/login",
                "campaign_id": None
            },
            "iocs": [
                {"type": "domain", "value": "paypa1-secure.com", "source": "internal_heuristic"},
                {"type": "url", "value": "https://paypa1-secure.com/login", "source": "internal_heuristic"}
            ],
            "evidence": [
                {"description": "Sender domain 'paypa1-secure.com' is a one-character lookalike of 'paypal.com'", "field_ref": "domain", "weight": 0.50},
                {"description": "Email requests urgent credential verification within 24 hours under threat of account lockout", "field_ref": "body_text", "weight": 0.35},
                {"description": "SPF and DKIM authentication failed for originating SMTP host", "field_ref": "headers", "weight": 0.20}
            ],
            "raw_reference": "uploads/2026-09-26/phish_sample_01.eml",
            "mitre_technique": None,
            "risk_level": None,
            "response_recommended": None
        }

        ev_net = {
            "event_id": f"evt_{uuid.uuid4()}",
            "source_engine": "network",
            "timestamp": "2026-09-26T09:14:30Z",
            "event_type": "new_device_login",
            "confidence": 0.88,
            "entities": {
                "user_email": "bipin.p@company.com",
                "ip_address": "203.0.113.42",
                "device_id": "dev_unknown_77",
                "session_id": "sess_9f8e7d2a",
                "campaign_id": None
            },
            "iocs": [
                {"type": "ip", "value": "203.0.113.42", "source": "internal_heuristic"}
            ],
            "evidence": [
                {"description": "Login occurred from an unrecognized device 'dev_unknown_77' not seen in 90 days", "field_ref": "device_id", "weight": 0.55},
                {"description": "Source IP 203.0.113.42 geolocation is 1,200km anomalous from user's standard location", "field_ref": "ip_address", "weight": 0.40}
            ],
            "raw_reference": "logs/auth/2026-09-26_auth.log#L4821",
            "mitre_technique": None,
            "risk_level": None,
            "response_recommended": None
        }

        ev_mal = {
            "event_id": f"evt_{uuid.uuid4()}",
            "source_engine": "malware",
            "timestamp": "2026-09-26T09:18:15Z",
            "event_type": "malware_detected",
            "confidence": 0.95,
            "entities": {
                "user_email": "bipin.p@company.com",
                "device_id": "dev_unknown_77",
                "file_hash_sha256": "4a7b9c1d2e3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
                "campaign_id": None
            },
            "iocs": [
                {"type": "file_hash", "value": "4a7b9c1d2e3f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b", "source": "internal_heuristic"}
            ],
            "evidence": [
                {"description": "Binary references high-risk process injection APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)", "field_ref": "imports", "weight": 0.50},
                {"description": "High Shannon entropy (7.65/8.0) confirms packed/encrypted executable sections", "field_ref": "entropy", "weight": 0.40},
                {"description": "Staged PowerShell download cradle attempting background payload retrieval", "field_ref": "script_content", "weight": 0.35}
            ],
            "raw_reference": "uploads/2026-09-26/staged_payload.exe",
            "mitre_technique": None,
            "risk_level": None,
            "response_recommended": None
        }

        c1 = correlation_engine.process_event(ev_email)
        c2 = correlation_engine.process_event(ev_net)
        c3 = correlation_engine.process_event(ev_mal)

        camp = correlation_engine.get_campaign(c1["entities"]["campaign_id"])
        evaluate_campaign(camp)
        return {
            "scenario": "phishing_lateral_movement",
            "title": "Multi-Stage Phishing & Lateral Movement Campaign",
            "campaign": camp.to_dict()
        }

    elif scenario_id == "ceo_deepfake_vishing":
        # Scenario 2: Deepfake Voice Impersonation of CEO targeting Finance
        ev_audio = {
            "event_id": f"evt_{uuid.uuid4()}",
            "source_engine": "deepfake_audio",
            "timestamp": "2026-09-26T10:05:00Z",
            "event_type": "deepfake_audio_detected",
            "confidence": 0.91,
            "entities": {
                "user_account_id": "acct_ceo_master",
                "user_email": "cfo@company.com",
                "campaign_id": None
            },
            "iocs": [],
            "evidence": [
                {"description": "Voice authenticity biometric score indicates 91% probability of synthetic neural voice clone", "field_ref": "audio_features", "weight": 0.55},
                {"description": "Caller claimed identity of CEO but call stream originated from unregistered VoIP gateway", "field_ref": "caller_id", "weight": 0.35},
                {"description": "Lure structure requests urgent wire transfer to offshore supplier account", "field_ref": "request_type", "weight": 0.30}
            ],
            "raw_reference": "uploads/2026-09-26/urgent_call_ceo.wav",
            "mitre_technique": None,
            "risk_level": None,
            "response_recommended": None
        }

        c_aud = correlation_engine.process_event(ev_audio)
        camp = correlation_engine.get_campaign(c_aud["entities"]["campaign_id"])
        evaluate_campaign(camp)
        return {
            "scenario": "ceo_deepfake_vishing",
            "title": "Executive Voice Deepfake Wire Fraud Campaign",
            "campaign": camp.to_dict()
        }

    elif scenario_id == "brute_force_exfiltration":
        # Scenario 3: SSH Brute Force -> Data Exfiltration Flow
        ev_brute = {
            "event_id": f"evt_{uuid.uuid4()}",
            "source_engine": "network",
            "timestamp": "2026-09-26T11:20:00Z",
            "event_type": "brute_force_attempt",
            "confidence": 0.89,
            "entities": {
                "ip_address": "198.51.100.23",
                "user_account_id": "service_backup_admin",
                "campaign_id": None
            },
            "iocs": [
                {"type": "ip", "value": "198.51.100.23", "source": "internal_heuristic"}
            ],
            "evidence": [
                {"description": "Over 48 failed authentication attempts observed in a 60-second window from IP 198.51.100.23", "field_ref": "ip_address", "weight": 0.65},
                {"description": "Targeted privileged backup service account across external SSH gateway", "field_ref": "user_account_id", "weight": 0.35}
            ],
            "raw_reference": "logs/network/2026-09-26_auth.log",
            "mitre_technique": None,
            "risk_level": None,
            "response_recommended": None
        }

        ev_exfil = {
            "event_id": f"evt_{uuid.uuid4()}",
            "source_engine": "network",
            "timestamp": "2026-09-26T11:25:30Z",
            "event_type": "data_exfiltration_attempt",
            "confidence": 0.92,
            "entities": {
                "ip_address": "198.51.100.23",
                "user_account_id": "service_backup_admin",
                "campaign_id": None
            },
            "iocs": [
                {"type": "ip", "value": "198.51.100.23", "source": "internal_heuristic"}
            ],
            "evidence": [
                {"description": "High-volume outbound flow (142.8 MB) transferred to untrusted external destination IP 198.51.100.23", "field_ref": "ip_address", "weight": 0.70},
                {"description": "Outbound connection initiated during abnormal non-business hours", "field_ref": "timestamp", "weight": 0.30}
            ],
            "raw_reference": "logs/netflow/2026-09-26_flow.csv",
            "mitre_technique": None,
            "risk_level": None,
            "response_recommended": None
        }

        c1 = correlation_engine.process_event(ev_brute)
        c2 = correlation_engine.process_event(ev_exfil)
        camp = correlation_engine.get_campaign(c1["entities"]["campaign_id"])
        evaluate_campaign(camp)
        return {
            "scenario": "brute_force_exfiltration",
            "title": "Brute Force & Exfiltration Attack",
            "campaign": camp.to_dict()
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario ID '{scenario_id}'")
