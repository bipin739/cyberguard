from typing import Dict, Any, Optional

# Standard MITRE ATT&CK Enterprise Matrix Technique Definitions
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    "T1566.002": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversary sends targeted emails containing deceptive URLs leading to credential harvesting or malware delivery sites."
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversary sends targeted emails with weaponized attachments designed to execute malicious payloads upon opening."
    },
    "T1656": {
        "id": "T1656",
        "name": "Impersonation (Deepfake / Social Engineering)",
        "tactic": "Initial Access / Defense Evasion",
        "description": "Adversary impersonates trusted individuals, executives, or internal staff using synthetic audio/video or social engineering."
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access / Persistence",
        "description": "Adversary obtains and abuses credentials of existing accounts to gain initial access or maintain persistence across network resources."
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempts multiple password combinations or credential stuffing attacks against authentication services."
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversary abuses command and script interpreters (PowerShell, Bash, Python, Windows Command Shell) to execute arbitrary code."
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": "Adversary injects malicious code into legitimate processes to evade defenses and run under privileged security contexts."
    },
    "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Adversary relies on actions by a user (e.g. running an executable, clicking a link) to initiate payload execution."
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": "Adversary communicates using application layer protocols (HTTP/HTTPS, DNS) to blend C2 beaconing traffic with normal operations."
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversary steals sensitive data by exfiltrating it over established command and control communication channels."
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversary encrypts data on target systems to interrupt availability and extort ransom payments."
    }
}


def map_event_to_mitre(event: Dict[str, Any]) -> Optional[str]:
    """
    Determines the most accurate MITRE ATT&CK technique ID for a given event
    based on its source_engine, event_type, and evidence.
    """
    engine = event.get("source_engine", "")
    ev_type = event.get("event_type", "")
    evidence_text = " ".join([e.get("description", "") for e in event.get("evidence", [])]).lower()

    if engine == "email":
        if "attachment" in ev_type or "attachment" in evidence_text:
            return "T1566.001"
        return "T1566.002"

    if engine == "deepfake_audio" or engine == "deepfake_video":
        return "T1656"

    if engine == "network":
        if ev_type == "brute_force_attempt":
            return "T1110"
        if ev_type == "data_exfiltration_attempt":
            return "T1041"
        if ev_type in ("new_device_login", "suspicious_login"):
            return "T1078"
        return "T1071"

    if engine == "malware":
        if "injection" in evidence_text or "virtualalloc" in evidence_text or "createremotethread" in evidence_text:
            return "T1055"
        if "script" in evidence_text or "powershell" in evidence_text:
            return "T1059"
        if "ransomware" in evidence_text or "shadows" in evidence_text:
            return "T1486"
        return "T1204"

    return None
