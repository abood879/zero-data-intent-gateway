import pytest
import asyncio
from sdk import protected_tool, SecurityViolationError, IdentitySpoofingError, DisambiguationRequiredError, audit_ledger
from app.main import app, evaluate_dof
from fastapi.testclient import TestClient

client = TestClient(app)

def test_unverified_context_injection_fails_closed():
    """Adversarial test: Agent attempts to inject forged role without signature."""
    @protected_tool(tool_name="admin_execute")
    def execute_maintenance():
        return "RUNNING"

    with pytest.raises(IdentitySpoofingError):
        execute_maintenance(__context__={"role": "superadmin", "__verified_signature__": False})

def test_e2e_unified_engine_parity_between_sdk_and_api():
    """Verifies complete decision parity between SDK decorator and Gateway HTTP API."""
    payload = {
        "tool": "wire_transfer",
        "parameters": {"amount": "50000.00"},
        "context": {"role": "finance_agent", "max_limit": "5000.00"}
    }
    
    # Check Gateway API response
    response = client.post(
        "/v1/evaluate",
        headers={"Authorization": "Bearer prod-deterministic-token-310"},
        json=payload
    )
    assert response.status_code == 200
    assert response.json()["status"] == "DENIED"
    assert response.json()["dof"] >= 2

    # Check SDK decorator on identical invocation
    @protected_tool(tool_name="wire_transfer")
    def perform_transfer(amount: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError):
        perform_transfer(amount="50000.00")

def test_tamper_evident_audit_ledger_records_sdk_denials():
    """Ensures denied operations are cryptographically chained in audit ledger."""
    initial_hash = audit_ledger.last_hash
    
    @protected_tool(tool_name="database_drop")
    def drop_table(target: str):
        return "DROPPED"

    with pytest.raises(SecurityViolationError):
        drop_table(target="customers")

    assert audit_ledger.last_hash != initial_hash, "Security Failure: Audit ledger hash did not advance on denial!"

@pytest.mark.asyncio
async def test_async_protected_tool_execution():
    """Verifies that async tools are strictly protected and fail closed."""
    @protected_tool(tool_name="database_drop")
    async def async_drop():
        await asyncio.sleep(0.01)
        return "DONE"

    with pytest.raises(SecurityViolationError):
        await async_drop()
