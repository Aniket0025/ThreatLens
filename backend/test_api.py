"""
test_api.py — Manual smoke tests for the URLShield API.
Run while the server is running: python test_api.py
"""

import requests

BASE = "http://127.0.0.1:5000"

TEST_URLS = [
    ("https://google.com", "Safe"),
    ("http://paypal-secure-login.verify-account.com/update", "Malicious"),
    ("http://192.168.1.1/admin", "Malicious/Suspicious"),
    ("https://github.com/login", "Safe/Suspicious"),
]


def test_health():
    r = requests.get(f"{BASE}/health", timeout=5)
    print(f"[health] {r.status_code} — {r.json()}")
    assert r.status_code == 200


def test_predict(url, expected_hint):
    r = requests.post(f"{BASE}/api/v1/predict", json={"url": url}, timeout=10)
    data = r.json()
    print(f"\n[predict] {url}")
    print(f"  Status     : {r.status_code}")
    print(f"  Prediction : {data.get('prediction')}  (expected ~{expected_hint})")
    print(f"  Risk score : {data.get('risk_score')}")
    print(f"  Risk level : {data.get('risk_level')}")
    print(f"  Explanation: {data.get('explanations', [])[:2]}")
    assert r.status_code == 200
    assert "prediction" in data
    assert "risk_score" in data


def test_missing_url():
    r = requests.post(f"{BASE}/api/v1/predict", json={}, timeout=5)
    print(f"\n[missing url] {r.status_code} — {r.json()}")
    assert r.status_code == 400


if __name__ == "__main__":
    print("═" * 55)
    print("  URLShield API Smoke Tests")
    print("═" * 55)
    test_health()
    test_missing_url()
    for url, hint in TEST_URLS:
        test_predict(url, hint)
    print("\n✓ All smoke tests passed.")
