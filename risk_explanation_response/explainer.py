from typing import Dict, Any, List
from correlation.correlator import Campaign


def generate_explanation(campaign: Campaign) -> Dict[str, Any]:
    """
    Generates an Explainable AI (XAI) multi-level narrative and evidence breakdown
    for a correlated security incident campaign.
    """
    if not campaign.events:
        return {
            "executive_summary": "No security events recorded in this campaign.",
            "attack_narrative": "No activity detected.",
            "evidence_breakdown": [],
            "confidence_justification": "N/A"
        }

    # Extract target identities
    targets = []
    if "user_email" in campaign.entities:
        targets.extend(list(campaign.entities["user_email"]))
    elif "user_account_id" in campaign.entities:
        targets.extend(list(campaign.entities["user_account_id"]))
    target_name = targets[0] if targets else "Organization Network Asset"

    # Extract threat vectors / engines
    engines = list(set(ev.get("source_engine", "") for ev in campaign.events))
    engine_names = ", ".join([eng.replace("_", " ").title() for eng in engines])

    # Extract all evidence items sorted by weight
    all_evidence = []
    for ev in campaign.events:
        for item in ev.get("evidence", []):
            all_evidence.append({
                "source_engine": ev.get("source_engine", "unknown"),
                "event_type": ev.get("event_type", ""),
                "description": item.get("description", ""),
                "field_ref": item.get("field_ref", "general"),
                "weight": item.get("weight", 0.0)
            })

    all_evidence.sort(key=lambda x: x.get("weight", 0.0), reverse=True)

    # 1. Executive Summary
    risk_level_str = (campaign.risk_level or "medium").upper()
    event_count = len(campaign.events)
    
    if len(engines) > 1:
        exec_summary = (
            f"CyberGuard detected a coordinated {risk_level_str} risk multi-stage cyber campaign targeting '{target_name}'. "
            f"The attack spans {event_count} correlated events across {engine_names} detection engines, demonstrating "
            f"an active multi-vector progression. Immediate containment is recommended."
        )
    else:
        exec_summary = (
            f"CyberGuard flagged a {risk_level_str} risk security threat targeting '{target_name}' via the {engine_names} engine. "
            f"Analysis of {event_count} correlated event(s) confirmed suspicious indicators with strong evidentiary weight."
        )

    # 2. Chronological Attack Narrative
    sorted_events = sorted(campaign.events, key=lambda e: e.get("timestamp", ""))
    narrative_steps = []

    for idx, ev in enumerate(sorted_events, start=1):
        engine = ev.get("source_engine", "").replace("_", " ").title()
        ev_type = ev.get("event_type", "").replace("_", " ").title()
        time_str = ev.get("timestamp", "")
        mitre_id = ev.get("mitre_technique")
        mitre_str = f" (MITRE: {mitre_id})" if mitre_id else ""
        
        # Pull top evidence for this event
        ev_items = ev.get("evidence", [])
        ev_desc = ev_items[0].get("description", "Anomalous activity detected.") if ev_items else "No specific evidence logged."
        
        narrative_steps.append(
            f"Stage {idx} [{engine} - {time_str}]: Detected {ev_type}{mitre_str}. Evidence: \"{ev_desc}\""
        )

    attack_narrative = "\n\n".join(narrative_steps)

    # 3. Confidence Justification
    avg_conf = sum(ev.get("confidence", 0.0) for ev in campaign.events) / len(campaign.events)
    conf_justification = (
        f"Overall risk assessment is driven by an average engine confidence of {int(avg_conf * 100)}% "
        f"across {len(campaign.events)} correlated telemetry events, corroborated by "
        f"{len(all_evidence)} distinct forensic indicators."
    )

    explanation = {
        "executive_summary": exec_summary,
        "attack_narrative": attack_narrative,
        "evidence_breakdown": all_evidence[:8],  # Top 8 most impactful signals
        "confidence_justification": conf_justification
    }

    campaign.explanation = explanation
    return explanation
