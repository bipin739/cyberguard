from typing import Dict, Any, List, Tuple
from correlation.correlator import Campaign

# High impact MITRE tactics multiplier
TACTIC_SEVERITY_WEIGHTS = {
    "Initial Access": 1.0,
    "Execution": 1.3,
    "Persistence": 1.2,
    "Privilege Escalation": 1.4,
    "Defense Evasion": 1.2,
    "Credential Access": 1.3,
    "Lateral Movement": 1.5,
    "Command and Control": 1.4,
    "Exfiltration": 1.6,
    "Impact": 1.7
}


def calculate_campaign_risk(campaign: Campaign) -> Tuple[float, str]:
    """
    Computes normalized risk score (0.0 - 100.0) and discrete risk level
    ('safe', 'low', 'medium', 'high', 'critical') for a given campaign.
    """
    if not campaign.events:
        return 0.0, "safe"

    # 1. Base Confidence Component (0 - 50 pts)
    confidences = [ev.get("confidence", 0.0) for ev in campaign.events]
    max_conf = max(confidences) if confidences else 0.0
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
    base_score = (max_conf * 35.0) + (avg_conf * 15.0)

    # 2. Multi-Vector Engine Amplifier (0 - 25 pts)
    distinct_engines = set(ev.get("source_engine", "") for ev in campaign.events)
    engine_count = len(distinct_engines)
    engine_score = min((engine_count - 1) * 12.5, 25.0) if engine_count > 1 else 0.0

    # 3. Kill Chain / MITRE Tactic Progression (0 - 20 pts)
    tactics = set()
    for tech in campaign.to_dict().get("mitre_techniques", []):
        tactics.add(tech.get("tactic", "Initial Access"))

    tactic_multiplier = 1.0
    for tac in tactics:
        for known_tac, weight in TACTIC_SEVERITY_WEIGHTS.items():
            if known_tac.lower() in tac.lower():
                tactic_multiplier = max(tactic_multiplier, weight)

    tactic_score = min(len(tactics) * 7.0 * (tactic_multiplier / 1.2), 20.0)

    # 4. Critical Target Entity Amplifier (0 - 5 pts)
    entity_score = 0.0
    all_entities_str = " ".join([
        str(v) for vals in campaign.entities.values() for v in vals
    ]).lower()
    if any(vip in all_entities_str for vip in ["ceo", "cfo", "admin", "root", "domain_controller", "master"]):
        entity_score = 5.0

    # Total Score computation
    total_score = min(base_score + engine_score + tactic_score + entity_score, 100.0)
    total_score = round(total_score, 1)

    # Discrete Risk Level assignment
    if total_score >= 80.0:
        risk_level = "critical"
    elif total_score >= 60.0:
        risk_level = "high"
    elif total_score >= 35.0:
        risk_level = "medium"
    elif total_score >= 15.0:
        risk_level = "low"
    else:
        risk_level = "safe"

    # Update campaign and its events
    campaign.risk_score = total_score
    campaign.risk_level = risk_level
    for ev in campaign.events:
        ev["risk_level"] = risk_level

    return total_score, risk_level
