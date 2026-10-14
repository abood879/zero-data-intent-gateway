import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)
AUTH_HEADERS = {"Authorization": "Bearer test-gateway-token"}


@pytest.fixture(autouse=True)
def configure_gateway_token(monkeypatch):
    monkeypatch.setenv("GATEWAY_API_TOKEN", "test-gateway-token")

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ACTIVE"

def test_tier1_intent_lock_dof0():
    payload = {
        "id": "TX-TEST-001",
        "amount": 1200.0,
        "vendor": "AWS_Cloud_Global",
        "department": "Engineering",
        "budget_cleared": True
    }
    response = client.post("/v1/governance/evaluate", headers=AUTH_HEADERS, json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "INTENT_LOCKED"
    assert data["degrees_of_freedom"] == 0
    assert data["tokens_consumed"] == 0
    assert "audit_hash" in data

def test_tier2_active_disambiguation_dof1():
    payload = {
        "id": "TX-TEST-002",
        "amount": 2500.0,
        "vendor": "AWS_Cloud_Global",
        "department": "Engineering",
        "budget_cleared": False
    }
    response = client.post("/v1/governance/evaluate", headers=AUTH_HEADERS, json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ACTIVE_DISAMBIGUATION_REQUIRED"
    assert data["degrees_of_freedom"] == 1
    assert data["required_field"] == "budget_cleared"

def test_tier3_deterministic_halt_dof_gt1():
    payload = {
        "id": "TX-TEST-003",
        "amount": 99999.0,
        "vendor": "UNAPPROVED_ROGUE_VENDOR",
        "department": "UnknownDept",
        "budget_cleared": False
    }
    response = client.post("/v1/governance/evaluate", headers=AUTH_HEADERS, json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HALTED_ARRESTING_HAZARD"
    assert data["degrees_of_freedom"] > 1

def test_strict_schema_rejection_extra_field():
    # محاولة تمرير حقل غير مسموح به (Prompt Injection / Bypass Attempt)
    payload = {
        "id": "TX-INJECT-001",
        "amount": 500.0,
        "vendor": "AWS_Cloud_Global",
        "department": "Engineering",
        "budget_cleared": True,
        "admin_override": True  # حقل دخيل محظور
    }
    response = client.post("/v1/governance/evaluate", headers=AUTH_HEADERS, json=payload)
    assert response.status_code == 422  # Unprocessable Entity via Pydantic

def test_prometheus_metrics_endpoint():
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "governance_transactions_total" in response.text
    assert "governance_latency_seconds" in response.text
