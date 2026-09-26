import json
from starlette.testclient import TestClient
from main import app

client = TestClient(app)

print("=" * 80)
print("CYBERGUARD FULL SYSTEM INTEGRATION TEST SUITE")
print("=" * 80)

# 1. Test Root Dashboard HTML
print("\n--- TEST 1: GET / (Dashboard UI) ---")
res_root = client.get("/")
print(f"Status Code: {res_root.status_code}")
assert res_root.status_code == 200
assert "CyberGuard" in res_root.text
assert "attackGraphCanvas" in res_root.text
print("[PASS] Root successfully served HTML Dashboard")

# 2. Test Ingestion Health
print("\n--- TEST 2: GET /health ---")
res_health = client.get("/health")
assert res_health.status_code == 200
assert res_health.json() == {"status": "ok"}
print("[PASS] Health endpoint OK")

# 3. Test Loading Scenario 1 (Phishing + Lateral Movement)
print("\n--- TEST 3: POST /api/load_scenario/phishing_lateral_movement ---")
res_sc1 = client.post("/api/load_scenario/phishing_lateral_movement")
assert res_sc1.status_code == 200
sc1_data = res_sc1.json()
camp_id1 = sc1_data["campaign"]["campaign_id"]
print(f"Loaded Campaign ID: {camp_id1}")
print(f"Campaign Title:     {sc1_data['campaign']['title']}")
print(f"Risk Score:         {sc1_data['campaign']['risk_score']}")
print(f"Risk Level:         {sc1_data['campaign']['risk_level']}")
assert sc1_data["campaign"]["risk_level"] in ("high", "critical")
print("[PASS] Scenario 1 loaded and correlated successfully")

# 4. Test Loading Scenario 2 (CEO Deepfake Vishing)
print("\n--- TEST 4: POST /api/load_scenario/ceo_deepfake_vishing ---")
res_sc2 = client.post("/api/load_scenario/ceo_deepfake_vishing")
assert res_sc2.status_code == 200
sc2_data = res_sc2.json()
camp_id2 = sc2_data["campaign"]["campaign_id"]
print(f"Loaded Campaign ID: {camp_id2}")
print(f"Campaign Title:     {sc2_data['campaign']['title']}")
print("[PASS] Scenario 2 loaded and correlated successfully")

# 5. Test Getting Stats
print("\n--- TEST 5: GET /api/stats ---")
res_stats = client.get("/api/stats")
assert res_stats.status_code == 200
stats = res_stats.json()
print(f"Total Campaigns: {stats['total_campaigns']}")
print(f"Total Events:    {stats['total_events']}")
print(f"Active Engines:  {len(stats['active_engines'])}")
assert stats["total_campaigns"] >= 2
assert stats["total_events"] >= 4
print("[PASS] Stats endpoint returning accurate metrics")

# 6. Test Getting All Campaigns
print("\n--- TEST 6: GET /api/campaigns ---")
res_camps = client.get("/api/campaigns")
assert res_camps.status_code == 200
campaigns = res_camps.json()
assert len(campaigns) >= 2
print(f"[PASS] Retrieved {len(campaigns)} active campaigns")

# 7. Test Campaign Detail and Attack Graph
print(f"\n--- TEST 7: GET /api/campaigns/{camp_id1}/graph ---")
res_graph = client.get(f"/api/campaigns/{camp_id1}/graph")
assert res_graph.status_code == 200
graph = res_graph.json()
print(f"Graph Nodes Count: {len(graph['nodes'])}")
print(f"Graph Edges Count: {len(graph['edges'])}")
assert len(graph["nodes"]) > 0
assert len(graph["edges"]) > 0
print("[PASS] Attack graph generated with nodes and edges")

# 8. Test Executing Automated Containment Action
print(f"\n--- TEST 8: POST /api/campaigns/{camp_id1}/respond ---")
res_respond = client.post(f"/api/campaigns/{camp_id1}/respond")
assert res_respond.status_code == 200
resp_data = res_respond.json()
print(f"Execution Status: {resp_data['status']}")
print(f"Action Executed:  {resp_data['action']}")
print(f"Logs:             {resp_data['execution_logs'][0]}")
assert resp_data["status"] == "executed"
assert len(resp_data["execution_logs"]) > 0
print("[PASS] Automated containment playbook executed successfully")

# 9. Test Direct /api/analyze Upload Endpoint
print("\n--- TEST 9: POST /api/analyze (Direct Ingestion & Analysis) ---")
sample_log = b"2026-09-26 12:00:00 198.51.100.99 sshd[9999]: Failed password for invalid user hacker\n"
res_analyze = client.post(
    "/api/analyze",
    files={"file": ("live_attack.log", sample_log, "text/plain")}
)
assert res_analyze.status_code == 200
analyze_data = res_analyze.json()
print(f"Analysis Event Type: {analyze_data['event']['event_type']}")
print(f"Assigned Campaign:   {analyze_data['campaign']['campaign_id']}")
assert analyze_data["event"]["source_engine"] == "network"
print("[PASS] Unified /api/analyze endpoint executed full multi-stage pipeline")

print("\n" + "=" * 80)
print("ALL SYSTEM INTEGRATION TESTS COMPLETED WITH 100% SUCCESS!")
print("=" * 80)
