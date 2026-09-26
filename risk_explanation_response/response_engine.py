from typing import Dict, Any, List, Optional
from correlation.correlator import Campaign

RESPONSE_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "quarantine_email": {
        "action": "quarantine_email",
        "title": "Quarantine Malicious Email",
        "priority": "P1",
        "description": "Purge and quarantine the phishing message across all enterprise mailboxes; block sender domain at mail gateway.",
        "steps": [
            "Search and remove message by Message-ID across Exchange/Google Workspace",
            "Add sender domain to tenant-wide perimeter blocklist",
            "Scan inbound mailbox logs for any other recipients"
        ]
    },
    "revoke_session_and_require_mfa": {
        "action": "revoke_session_and_require_mfa",
        "title": "Revoke Session & Enforce MFA",
        "priority": "P0",
        "description": "Immediately terminate all active SSO/OAuth sessions for the compromised user and force step-up MFA challenge.",
        "steps": [
            "Invalidate active OAuth2 refresh tokens and session cookies via IAM API",
            "Flag user account for mandatory password reset upon next login",
            "Trigger real-time push notification to user's registered authenticator app"
        ]
    },
    "isolate_endpoint": {
        "action": "isolate_endpoint",
        "title": "Network Quarantine Endpoint",
        "priority": "P0",
        "description": "Isolate the compromised workstation from the corporate LAN/VLAN to prevent lateral movement.",
        "steps": [
            "Apply host-based firewall isolation rules (allow only EDR management traffic)",
            "Terminate suspicious processes referencing payload hash",
            "Initiate full forensically-sound memory and disk artifact snapshot"
        ]
    },
    "block_ip_at_firewall": {
        "action": "block_ip_at_firewall",
        "title": "Block Malicious IP at Perimeter",
        "priority": "P1",
        "description": "Inject dynamic firewall block rule against attacking IP address at perimeter edge and WAF.",
        "steps": [
            "Add source IP to perimeter NGFW dynamic block group",
            "Drop all stateful connections originating from or destined to IP",
            "Check threat intelligence feeds for associated ASN infrastructure"
        ]
    },
    "quarantine_and_reset_credentials": {
        "action": "quarantine_and_reset_credentials",
        "title": "Full Incident Containment & Credential Reset",
        "priority": "P0",
        "description": "Execute coordinated response: Revoke sessions, reset passwords, quarantine messages, and isolate active IP.",
        "steps": [
            "Revoke all active user sessions and reset credentials",
            "Quarantine phishing messages and block malicious domains",
            "Blacklist source IP address on firewall and VPN gateways",
            "Notify SOC incident handler and open high-priority containment ticket"
        ]
    }
}


def recommend_response(campaign: Campaign) -> Dict[str, Any]:
    """
    Selects the optimal automated response action and playbook for a campaign,
    and updates the campaign and event records.
    """
    if not campaign.events:
        return {
            "recommended_action": None,
            "playbook": None,
            "action_items": []
        }

    engines = set(ev.get("source_engine", "") for ev in campaign.events)
    risk_level = campaign.risk_level or "low"

    # Decision Matrix
    if len(engines) >= 2 and risk_level in ("high", "critical"):
        action = "quarantine_and_reset_credentials"
    elif "network" in engines and any(ev.get("event_type") in ("new_device_login", "suspicious_login", "brute_force_attempt") for ev in campaign.events):
        action = "revoke_session_and_require_mfa"
    elif "malware" in engines:
        action = "isolate_endpoint"
    elif "email" in engines:
        action = "quarantine_email"
    elif "ip_address" in campaign.entities:
        action = "block_ip_at_firewall"
    else:
        action = "revoke_session_and_require_mfa"

    playbook = RESPONSE_PLAYBOOKS.get(action, RESPONSE_PLAYBOOKS["quarantine_email"])

    # Update campaign and events
    campaign.response_recommended = action
    for ev in campaign.events:
        if not ev.get("response_recommended"):
            ev["response_recommended"] = action

    # Build actionable checklist
    action_items = []
    if "user_email" in campaign.entities:
        for u in campaign.entities["user_email"]:
            action_items.append(f"Revoke active credentials for user {u}")
    if "ip_address" in campaign.entities:
        for ip in campaign.entities["ip_address"]:
            action_items.append(f"Block IP {ip} on Edge Firewall")
    if "domain" in campaign.entities:
        for d in campaign.entities["domain"]:
            action_items.append(f"Add domain '{d}' to DNS sinkhole")
    if "file_hash_sha256" in campaign.entities:
        for h in campaign.entities["file_hash_sha256"]:
            action_items.append(f"Add file hash {h[:16]}... to EDR blocklist")

    return {
        "recommended_action": action,
        "playbook": playbook,
        "action_items": action_items
    }
