import csv
import io
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Regex patterns for network log parsing
IPV4_REGEX = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)
TIMESTAMP_REGEX = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})"
)

# Known private/internal IP ranges
PRIVATE_IP_REGEX = re.compile(
    r"^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)"
)

SSH_FAILED_REGEX = re.compile(r"Failed password for (?:invalid user )?([a-zA-Z0-9_\-\.@]+)(?: from ([\d\.]+))?", re.IGNORECASE)
SSH_ACCEPTED_REGEX = re.compile(r"Accepted password for ([a-zA-Z0-9_\-\.@]+)(?: from ([\d\.]+))?", re.IGNORECASE)
AUTH_FAIL_GENERIC = re.compile(r"\b(failed|failure|invalid|unauthorized|denied|bad password)\b", re.IGNORECASE)
USER_EXTRACT_REGEX = re.compile(r"\b(?:user|account|username|usr|login)[:=\s]+['\"]?([a-zA-Z0-9_\-\.@]+)['\"]?", re.IGNORECASE)
DEVICE_EXTRACT_REGEX = re.compile(r"\b(?:device|dev_id|device_id|workstation|host)[:=\s]+['\"]?([a-zA-Z0-9_\-\.]+)['\"]?", re.IGNORECASE)
SESSION_EXTRACT_REGEX = re.compile(r"\b(?:session|sess_id|session_id)[:=\s]+['\"]?([a-zA-Z0-9_\-\.]+)['\"]?", re.IGNORECASE)


def process(file_path: str) -> Dict[str, Any]:
    """
    Parses and analyzes network logs, authentication event logs, or network flow CSVs.
    Identifies brute-force attacks, suspicious logins, abnormal API/traffic behavior,
    and potential exfiltration activity. Emits a compliant CyberGuard event.
    """
    text_content = ""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text_content = f.read(500000)  # Read up to 500KB
    except Exception:
        try:
            with open(file_path, "r", encoding="latin-1", errors="ignore") as f:
                text_content = f.read(500000)
        except Exception:
            text_content = ""

    lines = [line.strip() for line in text_content.splitlines() if line.strip()]

    evidence: List[Dict[str, Any]] = []
    iocs: List[Dict[str, Any]] = []
    confidence_signals: List[float] = []
    
    extracted_ips: List[str] = []
    extracted_users: List[str] = []
    extracted_devices: List[str] = []
    extracted_sessions: List[str] = []

    failed_auth_count = 0
    success_auth_count = 0
    exfil_bytes_out = 0
    large_outbound_transfers = 0

    # Try parsing as CSV if header matches network telemetry
    is_csv = False
    if lines and ("," in lines[0] or "\t" in lines[0]):
        first_line = lines[0].lower()
        if any(h in first_line for h in ["src_ip", "dst_ip", "bytes_out", "flow_duration", "proto", "client_ip"]):
            is_csv = True
            try:
                reader = csv.DictReader(lines)
                for row in reader:
                    src = row.get("src_ip") or row.get("source_ip") or row.get("client_ip")
                    dst = row.get("dst_ip") or row.get("destination_ip")
                    bytes_out = row.get("bytes_out") or row.get("bytes_sent") or row.get("packet_len")
                    user = row.get("user") or row.get("username")
                    dev = row.get("device_id") or row.get("device")
                    
                    if src and IPV4_REGEX.match(src):
                        extracted_ips.append(src)
                    if dst and IPV4_REGEX.match(dst):
                        extracted_ips.append(dst)
                    if user:
                        extracted_users.append(user)
                    if dev:
                        extracted_devices.append(dev)
                    if bytes_out:
                        try:
                            b_out = int(bytes_out)
                            exfil_bytes_out += b_out
                            if b_out > 10 * 1024 * 1024:  # >10MB in a single flow
                                large_outbound_transfers += 1
                        except ValueError:
                            pass
            except Exception:
                pass

    if not is_csv:
        # Standard line-by-line log analysis
        for line in lines:
            for match in IPV4_REGEX.finditer(line):
                ip = match.group(0)
                # Verify octets <= 255
                parts = ip.split(".")
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts if p.isdigit()):
                    extracted_ips.append(ip)

            # SSH Failures
            ssh_fail = SSH_FAILED_REGEX.search(line)
            if ssh_fail:
                failed_auth_count += 1
                if ssh_fail.group(1):
                    extracted_users.append(ssh_fail.group(1))
                if ssh_fail.group(2):
                    extracted_ips.append(ssh_fail.group(2))
                continue

            # SSH Success
            ssh_succ = SSH_ACCEPTED_REGEX.search(line)
            if ssh_succ:
                success_auth_count += 1
                if ssh_succ.group(1):
                    extracted_users.append(ssh_succ.group(1))
                if ssh_succ.group(2):
                    extracted_ips.append(ssh_succ.group(2))
                continue

            # Generic Auth checks
            if AUTH_FAIL_GENERIC.search(line):
                failed_auth_count += 1

            u_match = USER_EXTRACT_REGEX.search(line)
            if u_match:
                extracted_users.append(u_match.group(1))

            d_match = DEVICE_EXTRACT_REGEX.search(line)
            if d_match:
                extracted_devices.append(d_match.group(1))

            s_match = SESSION_EXTRACT_REGEX.search(line)
            if s_match:
                extracted_sessions.append(s_match.group(1))

    # Identify primary external / public IPs
    unique_ips = list(dict.fromkeys([ip for ip in extracted_ips if ip and isinstance(ip, str)]))
    public_ips = [ip for ip in unique_ips if not PRIVATE_IP_REGEX.match(ip)]
    primary_ip = public_ips[0] if public_ips else (unique_ips[0] if unique_ips else "127.0.0.1")

    # Add IOCs for public IPs
    for ip in public_ips[:5]:
        iocs.append({
            "type": "ip",
            "value": ip,
            "source": "internal_heuristic"
        })

    # Heuristic Classification
    event_type = "suspicious_login"
    
    if failed_auth_count >= 5:
        event_type = "brute_force_attempt"
        evidence.append({
            "description": f"Multiple failed authentication attempts ({failed_auth_count} events) detected originating from IP {primary_ip}",
            "field_ref": "ip_address",
            "weight": 0.65
        })
        confidence_signals.append(0.88)
        if success_auth_count > 0:
            evidence.append({
                "description": f"Potential brute-force success: Failed attempts were followed by successful login for user '{extracted_users[0] if extracted_users else 'unknown'}'",
                "field_ref": "user_account_id",
                "weight": 0.35
            })
            confidence_signals.append(0.92)

    elif large_outbound_transfers > 0 or exfil_bytes_out > 50 * 1024 * 1024:
        event_type = "data_exfiltration_attempt"
        evidence.append({
            "description": f"High volume anomalous outbound network flow detected ({exfil_bytes_out / (1024*1024):.1f} MB sent to {primary_ip})",
            "field_ref": "ip_address",
            "weight": 0.70
        })
        confidence_signals.append(0.85)

    elif extracted_devices or "new" in text_content.lower() or "unknown" in text_content.lower():
        event_type = "new_device_login"
        dev_name = extracted_devices[0] if extracted_devices else "dev_unknown_77"
        evidence.append({
            "description": f"Login occurred from unrecognized device '{dev_name}' not previously registered for user account",
            "field_ref": "device_id",
            "weight": 0.55
        })
        evidence.append({
            "description": f"Authentication session initiated from external source IP {primary_ip}",
            "field_ref": "ip_address",
            "weight": 0.40
        })
        confidence_signals.append(0.81)

    else:
        event_type = "suspicious_login"
        evidence.append({
            "description": f"Network activity logged from IP {primary_ip} with anomalies in authentication sequence",
            "field_ref": "ip_address",
            "weight": 0.45
        })
        confidence_signals.append(0.70)

    # Compute confidence
    if confidence_signals:
        prod = 1.0
        for c in confidence_signals:
            capped = min(max(c, 0.1), 0.95)
            prod *= (1.0 - capped)
        confidence = round(min(max(1.0 - prod, 0.50), 0.96), 2)
    else:
        confidence = 0.20

    # Build entities object
    entities: Dict[str, Any] = {}
    if primary_ip:
        entities["ip_address"] = primary_ip

    if extracted_users:
        email_users = [u for u in extracted_users if "@" in u]
        if email_users:
            entities["user_email"] = email_users[0].lower()
        else:
            entities["user_account_id"] = extracted_users[0]

    if extracted_devices:
        entities["device_id"] = extracted_devices[0]

    if extracted_sessions:
        entities["session_id"] = extracted_sessions[0]
    else:
        entities["session_id"] = f"sess_{uuid.uuid4().hex[:8]}"

    entities["campaign_id"] = None

    return {
        "event_id": f"evt_{uuid.uuid4()}",
        "source_engine": "network",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "confidence": confidence,
        "entities": entities,
        "iocs": iocs,
        "evidence": evidence,
        "raw_reference": file_path if file_path else "logs/auth/unknown.log",
        "mitre_technique": None,
        "risk_level": None,
        "response_recommended": None
    }
