import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import init_db

init_db()
client = TestClient(app)


def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "NPM Shield AI"


def test_settings_endpoint():
    response = client.get("/api/settings")
    assert response.status_code == 200
    data = response.json()
    assert "app_name" in data
    assert "backend_status" in data


def test_overview_endpoint():
    response = client.get("/api/overview")
    assert response.status_code == 200
    data = response.json()
    assert "total_scanned" in data
    assert "risk_distribution" in data


def test_scan_package_validation_empty():
    response = client.post("/api/scans/package", json={"package_name": ""})
    assert response.status_code == 400


def test_scan_package_demo_mode():
    response = client.post("/api/scans/package", json={"package_name": "chalk", "is_demo": True})
    assert response.status_code == 200
    data = response.json()
    assert data["package_name"] == "chalk"
    assert data["status"] == "completed"
    assert data["is_demo"] is True


def test_scan_history_and_export():
    # Scan demo malicious
    resp = client.post("/api/scans/package", json={"package_name": "evil-demo", "is_demo": True})
    assert resp.status_code == 200
    scan_id = resp.json()["id"]

    # History
    h_resp = client.get("/api/scans")
    assert h_resp.status_code == 200
    scans = h_resp.json()
    assert any(s["id"] == scan_id for s in scans)

    # Export JSON
    exp_json = client.get(f"/api/scans/{scan_id}/export?format=json")
    assert exp_json.status_code == 200
    assert "evil-demo" in exp_json.text

    # Export CSV
    exp_csv = client.get(f"/api/scans/{scan_id}/export?format=csv")
    assert exp_csv.status_code == 200
    assert "evil-demo" in exp_csv.text
