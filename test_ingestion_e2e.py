import io
import json
import os
from pathlib import Path
from starlette.testclient import TestClient
from main import app

client = TestClient(app)

print("=" * 75)
print("CYBERGUARD INGESTION LAYER (v0) - ACCEPTANCE TEST SUITE")
print("=" * 75)

# TEST 1: Health Check Endpoint
print("\n--- TEST 1: GET /health ---")
print("Request: GET http://127.0.0.1:8000/health")
resp1 = client.get("/health")
print(f"Response Status: {resp1.status_code}")
print(f"Response Body:   {resp1.text}")
assert resp1.status_code == 200, f"Health check failed: {resp1.status_code}"
assert resp1.json() == {"status": "ok"}, "Health check payload mismatch"
print("[PASS] TEST 1: /health returned HTTP 200 and {'status': 'ok'}")

# TEST 2: Multi-file Upload, Magic-Byte Detection & Routing
print("\n--- TEST 2: Multi-File Upload, Magic-Byte Detection & Routing ---")

test_files = [
    {
        "name": "sample_document.docx",
        "content": b"PK\x03\x04\x14\x00\x06\x00Fake docx payload bytes for testing",
        "expected_engine": "threat_intel",
        "expected_event_type": "unclassified_file",
        "desc": "ZIP/DOCX Signature (PK\\x03\\x04) -> unclassified_file"
    },
    {
        "name": "invoice_attachment.pdf",
        "content": b"%PDF-1.7\nFake PDF header and stream for testing",
        "expected_engine": "threat_intel",
        "expected_event_type": "unclassified_file",
        "desc": "PDF Signature (%PDF) -> unclassified_file"
    },
    {
        "name": "payload_test.exe",
        "content": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00Windows PE Executable binary",
        "expected_engine": "malware",
        "expected_event_type": "malware_detected",
        "desc": "Windows PE Executable Signature (MZ Header)"
    },
    {
        "name": "phishing_sample.eml",
        "content": b"From: ceo@paypal-security.org\nTo: finance@victim-corp.com\nSubject: Urgent Wire Transfer Required\nDate: Sat, 26 Sep 2026 08:30:00 +0000\n\nPlease transfer immediately.",
        "expected_engine": "email",
        "expected_event_type": "phishing_email_detected",
        "desc": "Plain-Text Email with RFC Headers (From:, To:, Subject:)"
    },
    {
        "name": "voice_call.wav",
        "content": b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00",
        "expected_engine": "deepfake_audio",
        "expected_event_type": "deepfake_audio_detected",
        "desc": "WAV Audio Magic Bytes (RIFF....WAVE)"
    },
    {
        "name": "auth_attack.log",
        "content": b"2026-09-26 09:14:30 203.0.113.42 sshd[4821]: Failed password for invalid user admin\n2026-09-26 09:14:32 203.0.113.42 sshd[4822]: Failed password for root",
        "expected_engine": "network",
        "expected_event_type": "suspicious_login",
        "desc": "Network Auth Log Line (Timestamp + IPv4)"
    }
]

for item in test_files:
    print(f"\nSubtest: Uploading '{item['name']}' ({item['desc']})")
    files = {"file": (item["name"], io.BytesIO(item["content"]), "application/octet-stream")}
    resp = client.post("/upload", files=files)
    print(f"Request:  POST /upload [filename={item['name']}, bytes={len(item['content'])}]")
    print(f"Response Status: {resp.status_code}")
    print(f"Response JSON:   {json.dumps(resp.json(), indent=2)}")
    assert resp.status_code == 200, f"Upload failed for {item['name']}"
    event = resp.json()
    assert event["source_engine"] == item["expected_engine"], f"Engine mismatch: expected {item['expected_engine']}, got {event['source_engine']}"
    assert event["event_type"] == item["expected_event_type"], f"Event type mismatch: expected {item['expected_event_type']}, got {event['event_type']}"
    print(f"[PASS] Correctly detected as '{event['source_engine']}' / '{event['event_type']}'")

# TEST 3: Misleading Extension Detection (e.g. PE/MZ executable saved as .txt)
print("\n--- TEST 3: Spoofed / Misleading Extension Test ---")
spoofed_filename = "harmless_notes.txt"
spoofed_content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xffPE_EXECUTABLE_HIDDEN_INSIDE"
print(f"Uploading file named '{spoofed_filename}' containing raw MZ binary magic bytes...")

files = {"file": (spoofed_filename, io.BytesIO(spoofed_content), "text/plain")}
resp3 = client.post("/upload", files=files)
print(f"Request:  POST /upload [filename={spoofed_filename}, header=MZ]")
print(f"Response Status: {resp3.status_code}")
print(f"Response JSON:   {json.dumps(resp3.json(), indent=2)}")
assert resp3.status_code == 200
event3 = resp3.json()
assert event3["source_engine"] == "malware", f"Spoofing check failed: got {event3['source_engine']}"
assert event3["event_type"] == "malware_detected"
print("[PASS] TEST 3: PE 'MZ' magic bytes took precedence over .txt extension -> correctly classified as 'malware'")

# TEST 4: Path Traversal Sanitization
print("\n--- TEST 4: Path Traversal Sanitization Test ---")
traversal_filename = "../../evil_shell.py"
traversal_content = b"print('malicious execution test')"
print(f"Uploading file with dangerous filename: '{traversal_filename}'")

files = {"file": (traversal_filename, io.BytesIO(traversal_content), "application/octet-stream")}
resp4 = client.post("/upload", files=files)
print(f"Request:  POST /upload [filename='{traversal_filename}']")
print(f"Response Status: {resp4.status_code}")
print(f"Response JSON:   {json.dumps(resp4.json(), indent=2)}")
assert resp4.status_code == 200
event4 = resp4.json()

# Verify that file was saved strictly inside uploads/ folder without path traversal
uploads_dir = Path(__file__).resolve().parent / "uploads"
raw_ref = event4.get("raw_reference", "")
print(f"Raw Reference Saved Path: {raw_ref}")
assert ".." not in Path(raw_ref).name, "Path traversal sequence leaked into filename"
assert Path(raw_ref).resolve().is_relative_to(uploads_dir.resolve()), "File saved outside uploads/ directory!"
print("[PASS] TEST 4: Filename sanitized and safely contained inside uploads/ directory")

# TEST 5: Large File Rejection (>50MB Limit)
print("\n--- TEST 5: Large File (>50MB) Rejection Test ---")
oversized_size = 51 * 1024 * 1024  # 51 MB
print(f"Generating simulated {oversized_size / (1024*1024):.1f}MB stream...")

class LargeDummyStream(io.RawIOBase):
    def __init__(self, total_size):
        self.total_size = total_size
        self.bytes_read = 0

    def readable(self):
        return True

    def readinto(self, b):
        if self.bytes_read >= self.total_size:
            return 0
        chunk_len = min(len(b), self.total_size - self.bytes_read)
        b[:chunk_len] = b"A" * chunk_len
        self.bytes_read += chunk_len
        return chunk_len

files = {"file": ("oversized_dump.bin", io.BufferedReader(LargeDummyStream(oversized_size)), "application/octet-stream")}
resp5 = client.post("/upload", files=files)
print(f"Request:  POST /upload [size={oversized_size} bytes / ~51MB]")
print(f"Response Status: {resp5.status_code}")
print(f"Response Body:   {resp5.text}")
assert resp5.status_code == 400, f"Expected HTTP 400, got {resp5.status_code}"
assert "50MB limit" in resp5.json().get("detail", ""), "Expected 50MB limit error message"
print("[PASS] TEST 5: Large file (>50MB) properly rejected with HTTP 400")

# TEST 6: Manual Force Type Override (?force_type=network)
print("\n--- TEST 6: Manual Force Type Override (?force_type=network) ---")
override_content = b"Ambiguous plain text or generic data"
files = {"file": ("generic_data.dat", io.BytesIO(override_content), "application/octet-stream")}
resp6 = client.post("/upload?force_type=network", files=files)
print(f"Request:  POST /upload?force_type=network [filename=generic_data.dat]")
print(f"Response Status: {resp6.status_code}")
print(f"Response JSON:   {json.dumps(resp6.json(), indent=2)}")
assert resp6.status_code == 200
event6 = resp6.json()
assert event6["source_engine"] == "network", f"Force type failed: got {event6['source_engine']}"
print("[PASS] TEST 6: force_type query parameter successfully routed to 'network' engine")

print("\n" + "=" * 75)
print("ALL ACCEPTANCE TESTS COMPLETED SUCCESSFULLY!")
print("=" * 75)
