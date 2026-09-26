import os
import json
from pathlib import Path
from starlette.testclient import TestClient
from main import app

client = TestClient(app)

print("=" * 75)
print("TESTING RESET & SINGLE PHISHING.EML UPLOAD FLOW")
print("=" * 75)

# Step 1: Call POST /api/reset
print("\n--- STEP 1: Calling POST /api/reset ---")
reset_resp = client.post("/api/reset")
print("Status Code:", reset_resp.status_code)
print("Response JSON:", reset_resp.json())
assert reset_resp.status_code == 200
assert reset_resp.json()["status"] == "ok"

# Step 2: Confirm 0 campaigns in stats
print("\n--- STEP 2: Verifying Stats are 0 ---")
stats_resp = client.get("/api/stats")
stats = stats_resp.json()
print("Stats:", stats)
assert stats["total_campaigns"] == 0
assert stats["total_events"] == 0

# Step 3: Upload ONLY phishing.eml via POST /api/analyze
print("\n--- STEP 3: Uploading ONLY phishing.eml ---")
eml_path = Path(__file__).resolve().parent / "phishing.eml"
with open(eml_path, "rb") as f:
    upload_resp = client.post(
        "/api/analyze",
        files={"file": ("phishing.eml", f, "message/rfc822")}
    )

print("Upload Status Code:", upload_resp.status_code)
upload_data = upload_resp.json()
print("Upload Response Event Type:", upload_data["event"]["event_type"])
print("Assigned Campaign ID:      ", upload_data["campaign"]["campaign_id"])
print("Campaign Title:            ", upload_data["campaign"]["title"])
print("Risk Level:                ", upload_data["campaign"]["risk_level"])
print("Risk Score:                ", upload_data["campaign"]["risk_score"])
print("MITRE Techniques:          ", [m["id"] for m in upload_data["campaign"]["mitre_techniques"]])

assert upload_resp.status_code == 200
assert upload_data["event"]["source_engine"] == "email"
assert upload_data["event"]["event_type"] == "phishing_email_detected"

# Step 4: Verify Dashboard State has EXACTLY 1 Campaign
print("\n--- STEP 4: Querying Dashboard State (/api/campaigns) ---")
camps_resp = client.get("/api/campaigns")
campaigns = camps_resp.json()
print(f"Total Campaigns Returned: {len(campaigns)}")
assert len(campaigns) == 1, f"Expected exactly 1 campaign, found {len(campaigns)}"

camp = campaigns[0]
print("\n--- RESULTING DASHBOARD STATE ---")
print(f"Campaign ID:           {camp['campaign_id']}")
print(f"Title:                 {camp['title']}")
print(f"Risk Score:            {camp['risk_score']} / 100.0 ({camp['risk_level'].upper()})")
print(f"Target Entities:       {camp['entities']}")
print(f"MITRE ATT&CK:          {[m['id'] + ': ' + m['name'] for m in camp['mitre_techniques']]}")
print(f"Recommended Response:  {camp['response_recommended']}")
print(f"Executive Summary:     {camp['explanation']['executive_summary']}")
print(f"Evidence Count:        {len(camp['explanation']['evidence_breakdown'])}")
for idx, ev in enumerate(camp['explanation']['evidence_breakdown'], start=1):
    print(f"  {idx}. [{ev['source_engine']}] (Weight: {ev['weight']}) {ev['description']}")

print("\n" + "=" * 75)
print("TEST COMPLETED SUCCESSFULLY!")
print("=" * 75)
