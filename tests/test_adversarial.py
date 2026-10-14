import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app.engine as engine
from app.main import app
from sdk import ZeroDataInterceptor


@pytest.fixture
def secured_client(monkeypatch):
    monkeypatch.setenv("GATEWAY_API_TOKEN", "test-gateway-token")
    monkeypatch.delenv("OPA_URL", raising=False)
    monkeypatch.setattr(engine.ledger, "append_record", lambda *_args: "TEST-AUDIT-HASH")
    return TestClient(app), {"Authorization": "Bearer test-gateway-token"}


def test_schema_poisoning_is_rejected(secured_client):
    client, headers = secured_client
    response = client.post(
        "/v1/governance/evaluate",
        headers=headers,
        json={
            "id": "TX-POISON",
            "amount": 1200.0,
            "vendor": "AWS_Cloud_Global",
            "department": "Engineering",
            "budget_cleared": True,
            "admin_override": True,
        },
    )

    assert response.status_code == 422


def test_financial_boundary_tampering_collapses_to_dof_above_one(secured_client):
    client, headers = secured_client
    response = client.post(
        "/v1/governance/evaluate",
        headers=headers,
        json={
            "id": "TX-BOUNDARY-TAMPER",
            "amount": 5000.01,
            "vendor": "UNAPPROVED_VENDOR",
            "department": "Engineering",
            "budget_cleared": False,
        },
    )

    assert response.status_code == 200
    decision = response.json()
    assert decision["status"] == "HALTED_ARRESTING_HAZARD"
    assert decision["degrees_of_freedom"] > 1


@pytest.mark.parametrize("authorization", [None, "Bearer wrong-token"])
def test_unauthorized_access_rejected(secured_client, authorization):
    client, _headers = secured_client
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.post(
        "/v1/governance/evaluate",
        headers=headers,
        json={
            "id": "TX-NO-TOKEN",
            "amount": 100.0,
            "vendor": "AWS_Cloud_Global",
            "department": "Engineering",
            "budget_cleared": True,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Unauthorized or Missing Gateway Token"


def test_application_startup_fails_without_gateway_token(monkeypatch):
    monkeypatch.delenv("GATEWAY_API_TOKEN", raising=False)

    with pytest.raises(
        RuntimeError,
        match="CRITICAL STARTUP FAILURE: GATEWAY_API_TOKEN is mandatory\\.",
    ):
        with TestClient(app):
            pass


def test_boot_fails_without_api_token(monkeypatch):
    monkeypatch.delenv("GATEWAY_API_TOKEN", raising=False)

    with pytest.raises(RuntimeError) as error:
        with TestClient(app):
            pass

    assert str(error.value) == (
        "CRITICAL STARTUP FAILURE: GATEWAY_API_TOKEN is mandatory."
    )


def test_sha256_audit_chain_tamper_detection():
    ledger = engine.HybridAuditLedger()
    ledger.append_record("TX-AUDIT-1", {"amount": 1200.0}, "INTENT_LOCKED")
    ledger.append_record("TX-AUDIT-2", {"amount": 700.0}, "HALTED_ARRESTING_HAZARD")

    assert all(len(record["hash"]) == 64 for record in ledger.chain)
    assert engine.verify_audit_chain(ledger.chain)

    tampered_chain = [dict(record) for record in ledger.chain]
    tampered_chain[0]["decision"] = "TAMPERED_DECISION"

    assert not engine.verify_audit_chain(tampered_chain)

    extra_field_chain = [dict(record) for record in ledger.chain]
    extra_field_chain[0]["unhashed_metadata"] = "tampered"

    assert not engine.verify_audit_chain(extra_field_chain)


def test_sdk_injects_token_and_runs_tool_only_after_gateway_allow(monkeypatch):
    monkeypatch.setenv("GATEWAY_API_TOKEN", "sdk-test-token")
    posted_requests = []

    class AllowedResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "INTENT_LOCKED"}

    def post(url, **kwargs):
        posted_requests.append((url, kwargs))
        return AllowedResponse()

    monkeypatch.setattr("sdk.requests.post", post)

    @ZeroDataInterceptor("http://gateway").guard
    def protected_tool(payload):
        return payload["id"]

    assert protected_tool({"id": "TX-SDK"}) == "TX-SDK"
    assert posted_requests[0][1]["headers"] == {
        "Authorization": "Bearer sdk-test-token"
    }


def test_opa_connection_failure_fails_closed(secured_client, monkeypatch):
    client, headers = secured_client
    monkeypatch.setenv("OPA_URL", "http://opa-unavailable:8181")

    class UnavailableOPAClient:
        def __enter__(self):
            raise OSError("OPA connection refused")

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(engine, "HTTPX_AVAILABLE", True)
    monkeypatch.setattr(engine.httpx, "Client", lambda **_kwargs: UnavailableOPAClient())

    response = client.post(
        "/v1/governance/evaluate",
        headers=headers,
        json={
            "id": "TX-OPA-OFFLINE",
            "amount": 100.0,
            "vendor": "AWS_Cloud_Global",
            "department": "Engineering",
            "budget_cleared": True,
        },
    )

    assert response.status_code == 503
    assert "transaction denied" in response.json()["detail"]


def test_explicit_opa_denial_never_falls_back_to_internal_policy(secured_client, monkeypatch):
    client, headers = secured_client
    monkeypatch.setenv("OPA_URL", "http://opa:8181")

    class DeniedResponse:
        status_code = 200

        def json(self):
            return {"result": {"allow": False, "disambiguation_required": False}}

    class DenyingOPAClient:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, *_args, **_kwargs):
            return DeniedResponse()

    monkeypatch.setattr(engine, "HTTPX_AVAILABLE", True)
    monkeypatch.setattr(engine.httpx, "Client", lambda **_kwargs: DenyingOPAClient())

    response = client.post(
        "/v1/governance/evaluate",
        headers=headers,
        json={
            "id": "TX-OPA-DENY",
            "amount": 100.0,
            "vendor": "AWS_Cloud_Global",
            "department": "Engineering",
            "budget_cleared": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "HALTED_POLICY_DENIED"
    assert response.json()["action"] == "DENY_BY_DEFAULT"
    assert response.json()["engine_source"] == "Open Policy Agent (Sidecar)"


def test_configured_redis_startup_failure_does_not_use_memory_fallback(monkeypatch):
    monkeypatch.setattr(engine, "REDIS_AVAILABLE", False)
    ledger = engine.HybridAuditLedger(redis_url="redis://redis:6379/0")

    with pytest.raises(engine.AuditLedgerUnavailable):
        ledger.append_record("TX-REDIS-STARTUP-FAILURE", {}, "INTENT_LOCKED")


def test_required_audit_ledger_failure_fails_closed(secured_client, monkeypatch):
    client, headers = secured_client

    def unavailable_ledger(*_args):
        raise engine.AuditLedgerUnavailable("Redis unavailable")

    monkeypatch.setattr(engine.ledger, "append_record", unavailable_ledger)
    response = client.post(
        "/v1/governance/evaluate",
        headers=headers,
        json={
            "id": "TX-REDIS-OFFLINE",
            "amount": 100.0,
            "vendor": "AWS_Cloud_Global",
            "department": "Engineering",
            "budget_cleared": True,
        },
    )

    assert response.status_code == 503
    assert "transaction denied" in response.json()["detail"]
def test_semantic_bypass_complete_params_blocked():
    """
    Adversarial test: Complete schema parameters bypassing authorization boundaries.
    Ensures that 100% syntactically valid parameters cannot bypass RBAC or financial
    thresholds, enforcing a deterministic Hard Halt (DoF >= 2).
    """
    from app.main import evaluate_dof
    
    # 1. Privilege Escalation: Valid parameters with unauthorized role
    malicious_payload = {
        "tool": "database_drop",
        "parameters": {"target_table": "users", "force": True},
        "context": {"role": "support_agent", "user_id": "agent_007"}
    }
    dof, reasons = evaluate_dof(malicious_payload)
    assert dof >= 2, "Security Breach: Unauthorized tool execution allowed because params were complete!"
    assert any("unauthorized" in r for r in reasons)

    # 2. Financial Drain Attack: Valid parameters exceeding critical organization threshold
    financial_drain_payload = {
        "tool": "wire_transfer",
        "parameters": {"amount": 50000, "beneficiary": "external_wallet"},
        "context": {"role": "finance_agent", "max_limit": 5000}
    }
    dof_fin, reasons_fin = evaluate_dof(financial_drain_payload)
    assert dof_fin >= 2, "Security Breach: High-value financial drain allowed because schema was valid!"
    assert any("exceeds critical threshold" in r for r in reasons_fin)


def test_protected_tool_decorator_blocks_unauthorized_execution():
    from sdk import SecurityViolationError, protected_tool

    executed = {"flag": False}

    @protected_tool(tool_name="database_drop")
    def dangerous_operation(target_table: str):
        executed["flag"] = True
        return "SUCCESS"

    with pytest.raises(SecurityViolationError) as exc_info:
        dangerous_operation(
            target_table="production_records",
            __context__={"role": "guest_agent"},
        )

    assert executed["flag"] is False
    assert "Execution blocked" in str(exc_info.value)


def test_protected_tool_checks_positional_arguments_before_execution():
    from sdk import SecurityViolationError, protected_tool

    executed = {"flag": False}

    @protected_tool(tool_name="wire_transfer")
    def transfer(amount: int):
        executed["flag"] = True
        return amount

    with pytest.raises(SecurityViolationError):
        transfer(
            50000,
            __context__={"role": "finance_agent", "max_limit": 50000},
        )

    assert executed["flag"] is False


def test_protected_tool_checks_keyword_expansion_before_execution():
    from sdk import SecurityViolationError, protected_tool

    executed = {"flag": False}

    @protected_tool(tool_name="wire_transfer")
    def transfer(**parameters):
        executed["flag"] = True
        return parameters

    with pytest.raises(SecurityViolationError):
        transfer(
            amount=50000,
            __context__={"role": "finance_agent", "max_limit": 50000},
        )

    assert executed["flag"] is False
