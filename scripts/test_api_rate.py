# Test funksional i rregullit API_RATE jashte dataset-it kryesor.
# Skripti krijon nje kopje te perkohshme te cloudtrail.json, i shton 25 thirrje API
# brenda te njejtes minute nga nje adrese testimi dhe ekzekuton detector.py mbi kopjen.
# Skedari origjinal nuk modifikohet, ndaj hash-i SHA-256 mbetet i pandryshuar.
import json
import os
import tempfile
import detector

TEST_IP = "203.0.113.10"   # adrese e rezervuar per dokumentim/testim (RFC 5737)
NUM_CALLS = 25             # mbi pragun THRESHOLD_API_RATE = 20

with open(detector.LOG_FILE) as f:
    data = json.load(f)

for i in range(NUM_CALLS):
    data["Events"].append({
        "EventTime":        f"2025-03-18T16:30:{i:02d}Z",
        "EventName":        "ListBuckets",
        "Username":         "api_rate_test",
        "SourceIPAddress":  TEST_IP,
        "AwsRegion":        "us-east-1",
        "ResponseElements": "Success",
        "EventType":        "AwsApiCall",
    })

with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
    json.dump(data, tmp)
    tmp_path = tmp.name

print(f"\nTest API_RATE: {NUM_CALLS} thirrje brenda nje minute nga {TEST_IP}")
print("-" * 50)
detector.LOG_FILE = tmp_path   # detektori lexon kopjen, jo skedarin origjinal
detector.detect()
os.remove(tmp_path)
