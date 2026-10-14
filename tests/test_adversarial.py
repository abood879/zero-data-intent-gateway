import asyncio
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app import main as gateway_main
from app.engine import governance_engine
from app.main import app
import sdk
from sdk import (
    AuditLedger,
    DisambiguationRequiredError,
    IdentitySpoofingError,
    SecurityViolationError,
    audit_ledger,
    protected_tool,
)

client = TestClient(app)
TEST_TOKEN = "adversarial-test-token"


def trusted_context(role: str, user_id: str = "test-user") -> dict[str, str]:
    return gateway_main._issue_trusted_context({"role": role, "user_id": user_id})


@pytest.fixture(autouse=True)
def configure_security_environment(monkeypatch):
    monkeypatch.setenv("GATEWAY_CONTEXT_HMAC_SECRET", "test-context-signing-secret")
    monkeypatch.setattr(
        gateway_main,
        "TOKEN_IDENTITY_MAP",
        {
            TEST_TOKEN: {
                "role": "finance_agent",
                "user_id": "adversarial-test-user",
            }
        },
    )


def test_unverified_context_injection_fails_closed():
    @protected_tool(tool_name="admin_execute")
    def execute_maintenance():
        return "RUNNING"

    with pytest.raises(IdentitySpoofingError):
        execute_maintenance(
            __context__={"role": "superadmin", "__verified_signature__": False}
        )

    with pytest.raises(IdentitySpoofingError):
        execute_maintenance()

    assert not hasattr(sdk, "sign_context")


def test_e2e_unified_engine_parity_between_sdk_and_api():
    payload = {
        "tool": "wire_transfer",
        "parameters": {"amount": "50000.00"},
        "context": {"role": "finance_agent", "max_limit": "5000.00"},
    }
    response = client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json=payload,
    )
    assert response.status_code == 200
    assert response.json()["status"] == "DENIED"
    assert response.json()["dof"] >= 2

    @protected_tool(tool_name="wire_transfer")
    def perform_transfer(amount: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError):
        perform_transfer(
            amount="50000.00",
            __context__=trusted_context("finance_agent"),
        )


def test_tamper_evident_audit_ledger_records_sdk_denials():
    initial_hash = audit_ledger.last_hash

    @protected_tool(tool_name="database_drop")
    def drop_table(target: str):
        return "DROPPED"

    with pytest.raises(SecurityViolationError):
        drop_table(
            target="customers",
            __context__=trusted_context("finance_agent"),
        )
    assert audit_ledger.last_hash != initial_hash


@pytest.mark.asyncio
async def test_async_protected_tool_execution():
    @protected_tool(tool_name="database_drop")
    async def async_drop():
        await asyncio.sleep(0.01)
        return "DONE"

    with pytest.raises(SecurityViolationError):
        await async_drop(__context__=trusted_context("agent"))


def test_unknown_tool_fails_closed_immediately():
    dof, violations, _ = governance_engine.evaluate(
        {
            "tool": "unregistered_tool",
            "parameters": {},
            "context": {"role": "agent"},
        }
    )

    assert dof >= 2
    assert violations == [
        "Security Invariant: Tool is unrecognized (Fail-Closed)"
    ]


def test_untrusted_context_spoofing_blocked_via_hmac():
    @protected_tool(tool_name="admin_execute")
    def execute_maintenance():
        return "RUNNING"

    with pytest.raises(IdentitySpoofingError):
        execute_maintenance(
            __context__={
                "role": "admin",
                "user_id": "spoofed",
                "__verified_signature__": True,
            }
        )

    tampered_context = gateway_main._issue_trusted_context(
        {"role": "admin", "user_id": "trusted-admin"}
    )
    tampered_context["role"] = "superadmin"
    with pytest.raises(IdentitySpoofingError):
        execute_maintenance(__context__=tampered_context)


def test_valid_hmac_signed_context_authorized():
    @protected_tool(tool_name="admin_execute")
    def execute_maintenance():
        return "RUNNING"

    context = gateway_main._issue_trusted_context(
        {"role": "admin", "user_id": "verified-admin"}
    )

    assert execute_maintenance(__context__=context) == "RUNNING"


def test_server_enforced_financial_limits_override_client_injection():
    response = client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "tool": "wire_transfer",
            "parameters": {"amount": "6000.00"},
            "context": {
                "role": "admin",
                "user_id": "attacker",
                "max_limit": "1000000.00",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["dof"] == 1
    assert any(
        "server-enforced limit (5000.00)" in item
        for item in response.json()["violations"]
    )


def test_tamper_evident_audit_ledger_hashes_parameters_atomically(tmp_path):
    ledger = AuditLedger(tmp_path / "audit_ledger.jsonl")
    params_a = {"amount": "100.00"}
    params_b = {"amount": "200.00"}
    first_hash = ledger.record(
        "wire_transfer",
        params_a,
        {"role": "finance_agent"},
        "POLICY_EVALUATED",
        dof=0,
        decision="APPROVED",
    )
    second_hash = ledger.record(
        "wire_transfer",
        params_b,
        {"role": "finance_agent"},
        "EXECUTION_SUCCESS",
        dof=0,
        decision="SUCCEEDED",
    )

    expected_digest = hashlib.sha256(
        json.dumps(
            params_a,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    assert ledger.chain[0]["params_digest"] == expected_digest
    assert ledger.chain[1]["prev_hash"] == first_hash
    assert second_hash != first_hash

    with ThreadPoolExecutor(max_workers=8) as executor:
        hashes = list(
            executor.map(
                lambda index: ledger.record(
                    "wire_transfer",
                    {"amount": str(index)},
                    {"role": "finance_agent"},
                    "EXECUTION_SUCCESS",
                    dof=0,
                    decision="SUCCEEDED",
                ),
                range(32),
            )
        )

    chain = ledger.chain
    assert len(hashes) == 32
    assert len({record["hash"] for record in chain}) == len(chain)
    assert all(
        chain[index]["prev_hash"] == chain[index - 1]["hash"]
        for index in range(1, len(chain))
    )
    assert ledger.last_hash == chain[-1]["hash"]


def test_max_allowed_dof_does_not_bypass_financial_step_up():
    identity = gateway_main._issue_trusted_context(
        {"role": "finance_agent", "user_id": "finance-user"}
    )

    @protected_tool(tool_name="wire_transfer", max_allowed_dof=1)
    def transfer(amount: str):
        return "TRANSFERRED"

    with pytest.raises(DisambiguationRequiredError):
        transfer(amount="6000.00", __context__=identity)

    token = gateway_main._issue_step_up_approval_token(
        tool="wire_transfer",
        parameters={"amount": "6000.00"},
        identity={"role": "finance_agent", "user_id": "finance-user"},
        expires_at=time.time() + 60,
    )
    assert (
        transfer(
            amount="6000.00",
            __context__=identity,
            step_up_approval_token=token,
        )
        == "TRANSFERRED"
    )
    assert audit_ledger.chain[-2]["decision"] == "STEP_UP_APPROVED"


def test_max_allowed_dof_cannot_bypass_security_invariants():
    @protected_tool(tool_name="wire_transfer", max_allowed_dof=99)
    def transfer(amount: str):
        return "TRANSFERRED"

    with pytest.raises(SecurityViolationError):
        transfer(
            amount="15000.00",
            __context__=trusted_context("finance_agent"),
        )


def test_tool_execution_failure_is_written_to_persistent_ledger(
    tmp_path, monkeypatch
):
    import sdk

    ledger_path = tmp_path / "audit_ledger.jsonl"
    ledger = AuditLedger(ledger_path)
    monkeypatch.setattr(sdk, "audit_ledger", ledger)
    context = gateway_main._issue_trusted_context(
        {"role": "admin", "user_id": "admin-user"}
    )

    @protected_tool(tool_name="admin_execute")
    def broken_operation():
        raise ValueError("execution failed for test")

    with pytest.raises(ValueError, match="execution failed for test"):
        broken_operation(__context__=context)

    events = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    assert [event["status"] for event in events] == [
        "POLICY_EVALUATED",
        "EXECUTION_FAILED",
    ]
    assert events[-1]["exception_summary"] == {
        "type": "ValueError",
        "message": "execution failed for test",
    }
    assert events[-1]["execution_latency"] >= 0


def test_persistent_audit_chain_continues_across_instances(tmp_path):
    ledger_path = tmp_path / "audit_ledger.jsonl"
    first = AuditLedger(ledger_path)
    first_hash = first.record(
        "admin_execute",
        {"operation": "first"},
        {"role": "admin", "user_id": "admin-user"},
        "POLICY_EVALUATED",
        dof=0,
        decision="APPROVED",
    )

    resumed = AuditLedger(ledger_path)
    assert resumed.last_hash == first_hash
    second_hash = resumed.record(
        "admin_execute",
        {"operation": "second"},
        {"role": "admin", "user_id": "admin-user"},
        "EXECUTION_SUCCESS",
        dof=0,
        decision="SUCCEEDED",
        execution_latency=0.01,
    )

    verified = AuditLedger(ledger_path)
    assert verified.last_hash == second_hash
    assert len(verified.chain) == 2
    assert verified.chain[1]["prev_hash"] == first_hash


def test_api_ignores_client_supplied_identity_on_legacy_path():
    response = client.post(
        "/v1/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "tool": "wire_transfer",
            "parameters": {"amount": "6000.00"},
            "context": {
                "role": "admin",
                "user_id": "attacker",
                "max_limit": "1000000.00",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["dof"] == 1


def test_legacy_evaluate_route_derives_identity_from_token_mapping():
    response = client.post(
        "/v1/governance/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "id": "TX-LEGACY-IDENTITY",
            "amount": 6000.0,
            "vendor": "AWS_Cloud_Global",
            "department": "Finance",
            "budget_cleared": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["degrees_of_freedom"] == 1


def test_evaluate_alias_uses_server_token_identity():
    response = client.post(
        "/evaluate",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        json={
            "tool": "wire_transfer",
            "parameters": {"amount": "6000.00"},
            "context": {"role": "admin", "max_limit": "999999.00"},
        },
    )

    assert response.status_code == 200
    assert response.json()["dof"] == 1
