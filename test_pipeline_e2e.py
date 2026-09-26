import json
from shared.schema_validator import validate_event
from correlation.correlator import correlation_engine
from risk_explanation_response import evaluate_campaign
from engines.email.engine import process as process_email
from engines.network.engine import process as process_network
from engines.malware.engine import process as process_malware

print("=" * 80)
print("CYBERGUARD FULL THREAT DETECTION & CORRELATION PIPELINE TEST")
print("=" * 80)

# STEP 1: Process Simulated Raw Threat Inputs Through Engines
print("\n--- STEP 1: Running Multi-Engine Threat Ingestion ---")

# 1. Email Engine Processing
import tempfile
with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w", encoding="utf-8") as f:
    f.write(
        "From: security-alerts@paypa1-secure.com\n"
        "To: bipin.p@company.com\n"
        "Subject: URGENT: Verify Your Account Credentials Immediately\n"
        "Date: Sat, 26 Sep 2026 09:12:00 +0000\n"
        "Authentication-Results: spf=fail (sender IP not authorized)\n\n"
        "Dear customer, your account will be suspended within 24 hours. "
        "Click here to verify: https://paypa1-secure.com/login"
    )
    email_path = f.name

ev1 = process_email(email_path)
print(f"[Email Engine] Generated Event: {ev1['event_type']} (Confidence: {ev1['confidence']})")
print(f"  Target: {ev1['entities'].get('user_email')} | Domain: {ev1['entities'].get('domain')}")
is_valid, errs = validate_event(ev1)
assert is_valid, f"Email event failed schema: {errs}"
print("  [PASS] Schema validation OK")

# 2. Network Engine Processing
with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w", encoding="utf-8") as f:
    f.write(
        "2026-09-26 09:14:30 203.0.113.42 sshd[4821]: Failed password for invalid user admin\n"
        "2026-09-26 09:14:32 203.0.113.42 sshd[4822]: Failed password for bipin.p@company.com\n"
        "2026-09-26 09:15:00 203.0.113.42 sshd[4823]: Accepted password for bipin.p@company.com port 22 ssh2 (device: dev_unknown_77)\n"
    )
    net_path = f.name

ev2 = process_network(net_path)
print(f"\n[Network Engine] Generated Event: {ev2['event_type']} (Confidence: {ev2['confidence']})")
print(f"  Target: {ev2['entities'].get('user_email')} | IP: {ev2['entities'].get('ip_address')} | Device: {ev2['entities'].get('device_id')}")
is_valid, errs = validate_event(ev2)
assert is_valid, f"Network event failed schema: {errs}"
print("  [PASS] Schema validation OK")

# 3. Malware Engine Processing
with tempfile.NamedTemporaryFile(suffix=".exe", delete=False, mode="wb") as f:
    # Simulated MZ header with high entropy / script injection signature
    f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"VirtualAlloc WriteProcessMemory CreateRemoteThread mimikatz sekurlsa powershell -w hidden -EncodedCommand AAAAAA==" * 10)
    malware_path = f.name

ev3 = process_malware(malware_path)
print(f"\n[Malware Engine] Generated Event: {ev3['event_type']} (Confidence: {ev3['confidence']})")
print(f"  SHA256: {ev3['entities'].get('file_hash_sha256')[:16]}...")
is_valid, errs = validate_event(ev3)
assert is_valid, f"Malware event failed schema: {errs}"
print("  [PASS] Schema validation OK")

# Link malware to the same user session for multi-stage correlation
ev3["entities"]["user_email"] = "bipin.p@company.com"

# STEP 2: Correlation Engine Processing
print("\n--- STEP 2: Correlating Events Into Attack Campaign ---")
correlated_ev1 = correlation_engine.process_event(ev1)
correlated_ev2 = correlation_engine.process_event(ev2)
correlated_ev3 = correlation_engine.process_event(ev3)

camp_id1 = correlated_ev1["entities"]["campaign_id"]
camp_id2 = correlated_ev2["entities"]["campaign_id"]
camp_id3 = correlated_ev3["entities"]["campaign_id"]

print(f"Event 1 Assigned Campaign ID: {camp_id1} (MITRE: {correlated_ev1['mitre_technique']})")
print(f"Event 2 Assigned Campaign ID: {camp_id2} (MITRE: {correlated_ev2['mitre_technique']})")
print(f"Event 3 Assigned Campaign ID: {camp_id3} (MITRE: {correlated_ev3['mitre_technique']})")

assert camp_id1 == camp_id2 == camp_id3, "Correlation failed to group events sharing entity 'bipin.p@company.com'!"
print(f"[PASS] All 3 multi-engine events successfully correlated into Campaign: {camp_id1}")

# STEP 3: Downstream Evaluation (Risk Scoring, Explainer, Response)
print("\n--- STEP 3: Downstream Risk Evaluation & Explainable AI ---")
campaign = correlation_engine.get_campaign(camp_id1)
evaluate_campaign(campaign)

print(f"Campaign Title:       {campaign.title}")
print(f"Campaign Risk Score: {campaign.risk_score} / 100.0")
print(f"Campaign Risk Level: {campaign.risk_level.upper()}")
print(f"Recommended Action:  {campaign.response_recommended}")

assert campaign.risk_level in ("high", "critical"), f"Expected high/critical risk level, got {campaign.risk_level}"

# Validate each updated event against schema
for ev in campaign.events:
    is_valid, errs = validate_event(ev)
    assert is_valid, f"Correlated event failed schema validation: {errs}"
print("[PASS] All correlated and enriched events strictly pass shared schema validation")

# STEP 4: Explainable AI Inspection
print("\n--- STEP 4: Explainable AI (XAI) Output Inspection ---")
explanation = campaign.explanation
print(f"\n[Executive Summary]:\n{explanation['executive_summary']}")
print(f"\n[Attack Narrative]:\n{explanation['attack_narrative']}")
print(f"\n[Top Evidence Breakdown]:")
for idx, item in enumerate(explanation['evidence_breakdown'][:4], start=1):
    print(f"  {idx}. [{item['source_engine']}] (Weight: {item['weight']}) {item['description']}")

# STEP 5: Visual Attack Graph
print("\n--- STEP 5: Attack Graph Construction ---")
attack_graph = correlation_engine.build_attack_graph(camp_id1)
print(f"Attack Graph Nodes: {len(attack_graph['nodes'])} | Edges: {len(attack_graph['edges'])}")
assert len(attack_graph['nodes']) >= 5, "Attack graph missing nodes"
assert len(attack_graph['edges']) >= 4, "Attack graph missing edges"
print("[PASS] Attack Graph correctly structured for visual rendering")

print("\n" + "=" * 80)
print("ALL END-TO-END PIPELINE ACCEPTANCE TESTS PASSED PERFECTLY!")
print("=" * 80)
